//! Verify the output of the pinned native supplier before compiling/linking.
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
struct Source {
    name: String,
    version: String,
    commit: String,
    archive_sha256: String,
    archive_bytes: u64,
}
#[derive(Deserialize)]
struct Target {
    crt: String,
    libraries: BTreeMap<String, String>,
}
#[derive(Deserialize)]
struct Lock {
    schema_version: u32,
    kind: String,
    sources: Vec<Source>,
    targets: BTreeMap<String, Target>,
    profile: String,
    linkage: String,
    features: Value,
}
#[derive(Deserialize)]
struct InstalledFile {
    path: String,
    kind: String,
    bytes: u64,
    sha256: String,
}
#[derive(Deserialize)]
struct Receipt {
    schema_version: u32,
    kind: String,
    target: String,
    profile: String,
    linkage: String,
    crt: String,
    lock_sha256: String,
    sources: Vec<Source>,
    features: Value,
    libraries: BTreeMap<String, String>,
    files: Vec<InstalledFile>,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn plain_metadata(path: &Path) -> io::Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(invalid("native prefix contains a symbolic link"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(invalid("native prefix contains a reparse point"));
        }
    }
    Ok(metadata)
}
fn safe_relative(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 512
        && path.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.+".contains(&b))
        })
}
fn collect(
    prefix: &Path,
    at: &Path,
    files: &mut BTreeSet<String>,
    entries: &mut usize,
) -> io::Result<()> {
    // An installed prefix is small; bounded traversal also rejects an accidental
    // toolchain root instead of walking an unrelated directory tree.
    if at.components().count() > prefix.components().count() + 12 {
        return Err(invalid("native prefix directory nesting exceeds budget"));
    }
    for entry in fs::read_dir(at)? {
        *entries += 1;
        if *entries > 4096 {
            return Err(invalid("native prefix directory entry budget exceeded"));
        }
        let path = entry?.path();
        let metadata = plain_metadata(&path)?;
        if metadata.is_dir() {
            collect(prefix, &path, files, entries)?;
        } else if metadata.is_file() {
            let relative = path.strip_prefix(prefix).map_err(io::Error::other)?;
            let relative = relative
                .to_str()
                .ok_or_else(|| invalid("non-UTF8 native prefix path"))?
                .replace('\\', "/");
            if !safe_relative(&relative) || !files.insert(relative) || files.len() > 2048 {
                return Err(invalid(
                    "invalid/duplicate native prefix path or file count",
                ));
            }
        } else {
            return Err(invalid("native prefix contains a special file"));
        }
    }
    Ok(())
}

/// Returns every checked input so Cargo will rerun if an installed file changes.
/// A receipt proves consistency with the local supplier run, not authenticity
/// against a malicious local account able to replace both libraries and receipt.
pub fn verify(prefix: &Path, lock_bytes: &[u8], target: &str) -> io::Result<Vec<PathBuf>> {
    if !plain_metadata(prefix)?.is_dir() {
        return Err(invalid("native prefix is not a directory"));
    }
    let lock: Lock = serde_json::from_slice(lock_bytes)?;
    if lock.schema_version != 1 || lock.kind != "nestlink-native-codecs-lock" {
        return Err(invalid("unsupported native source lock"));
    }
    let expected = lock
        .targets
        .get(target)
        .ok_or_else(|| invalid("native target has no reviewed supplier configuration"))?;
    let receipt_path = prefix.join("nestlink-codecs.json");
    let metadata = plain_metadata(&receipt_path)?;
    if !metadata.is_file() || metadata.len() > 4 * 1024 * 1024 {
        return Err(invalid("native receipt exceeds budget"));
    }
    let receipt: Receipt = serde_json::from_slice(&fs::read(&receipt_path)?)?;
    if receipt.schema_version != 1
        || receipt.kind != "nestlink-native-codecs"
        || receipt.target != target
        || receipt.profile != lock.profile
        || receipt.linkage != lock.linkage
        || receipt.crt != expected.crt
        || receipt.lock_sha256 != digest(lock_bytes)
        || receipt.features != lock.features
        || receipt.libraries != expected.libraries
        || receipt.sources.len() != lock.sources.len()
        || receipt.sources.is_empty()
        || receipt.files.len() > 2047
    {
        return Err(invalid(
            "native receipt differs from pinned target, sources or features",
        ));
    }
    let mut source_names = BTreeSet::new();
    for source in &receipt.sources {
        let pinned = lock
            .sources
            .iter()
            .find(|s| s.name == source.name)
            .ok_or_else(|| invalid("unknown native source"))?;
        if !source_names.insert(&source.name)
            || source.version != pinned.version
            || source.commit != pinned.commit
            || source.archive_sha256 != pinned.archive_sha256
            || source.archive_bytes != pinned.archive_bytes
        {
            return Err(invalid(
                "native source receipt differs from locked upstream",
            ));
        }
    }
    let mut installed = BTreeSet::new();
    collect(prefix, prefix, &mut installed, &mut 0)?;
    installed.remove("nestlink-codecs.json");
    let mut declared = BTreeMap::new();
    let mut inputs = vec![receipt_path];
    let mut total = 0u64;
    for record in &receipt.files {
        if !safe_relative(&record.path)
            || !matches!(record.kind.as_str(), "library" | "header" | "metadata")
            || declared.insert(record.path.clone(), &record.kind).is_some()
        {
            return Err(invalid("invalid/duplicate native receipt file"));
        }
        let path = prefix.join(&record.path);
        // collect() has already rejected links in every path component.
        if !installed.contains(&record.path) {
            return Err(invalid("declared native prefix file is missing"));
        }
        total = total
            .checked_add(record.bytes)
            .ok_or_else(|| invalid("native prefix size overflow"))?;
        if total > 512 * 1024 * 1024 || record.sha256.len() != 64 {
            return Err(invalid(
                "native prefix exceeds byte budget or has invalid hash",
            ));
        }
        let file = fs::File::open(&path)?;
        if file.metadata()?.len() != record.bytes {
            return Err(invalid("native installed file size mismatch"));
        }
        let mut file = file.take(record.bytes + 1);
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            let length = file.read(&mut buffer)?;
            if length == 0 {
                break;
            }
            hash.update(&buffer[..length]);
        }
        if format!("{:x}", hash.finalize()) != record.sha256 {
            return Err(invalid("native installed file hash mismatch"));
        }
        inputs.push(path);
    }
    if installed != declared.keys().cloned().collect() {
        return Err(invalid("undeclared native prefix file"));
    }
    for library in expected.libraries.values() {
        if declared.get(library).map(|v| v.as_str()) != Some("library") {
            return Err(invalid("missing pinned native library"));
        }
    }
    for header in [
        "include/vpx/vpx_encoder.h",
        "include/vpx/vpx_decoder.h",
        "include/opus/opus.h",
    ] {
        if declared.get(header).map(|v| v.as_str()) != Some("header") {
            return Err(invalid("missing pinned native header"));
        }
    }
    Ok(inputs)
}
