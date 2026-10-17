#[path = "../build_support.rs"]
mod build_support;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs, io, path::Path};

const TARGET: &str = "x86_64-unknown-linux-gnu";
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn fixture(prefix: &Path) -> io::Result<(Vec<u8>, Value)> {
    let sources = json!([{ "name": "test-codec", "version": "1", "commit": "fixed-commit",
        "archive_sha256": "fixed-sha256", "archive_bytes": 10 }]);
    let libraries = json!({"vpx":"lib/libvpx.a", "opus":"lib/libopus.a"});
    let lock = serde_json::to_vec(
        &json!({"schema_version":1, "kind":"nestlink-native-codecs-lock",
        "sources":sources, "targets": {TARGET: {"crt":"system", "libraries":libraries}},
        "profile":"release", "linkage":"static", "features":{"vp8":true,"vp9":false}}),
    )?;
    let mut files = Vec::new();
    for (path, kind) in [
        ("lib/libvpx.a", "library"),
        ("lib/libopus.a", "library"),
        ("include/vpx/vpx_encoder.h", "header"),
        ("include/vpx/vpx_decoder.h", "header"),
        ("include/opus/opus.h", "header"),
    ] {
        let absolute = prefix.join(path);
        fs::create_dir_all(
            absolute
                .parent()
                .ok_or_else(|| io::Error::other("no parent"))?,
        )?;
        fs::write(absolute, b"fixture")?;
        files.push(json!({"path":path,"kind":kind,"bytes":7,"sha256":hash(b"fixture")}));
    }
    let receipt = json!({"schema_version":1,"kind":"nestlink-native-codecs", "target":TARGET,
        "profile":"release","linkage":"static","crt":"system", "lock_sha256":hash(&lock),
        "sources":sources,"libraries":libraries,"features":{"vp8":true,"vp9":false},"files":files});
    write_receipt(prefix, &receipt)?;
    Ok((lock, receipt))
}
fn write_receipt(prefix: &Path, receipt: &Value) -> io::Result<()> {
    fs::write(
        prefix.join("nestlink-codecs.json"),
        serde_json::to_vec(receipt)?,
    )
}

#[test]
fn correct_prefix_and_tampered_library() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let (lock, _) = fixture(root.path())?;
    assert_eq!(build_support::verify(root.path(), &lock, TARGET)?.len(), 6);
    fs::write(root.path().join("lib/libvpx.a"), b"changed")?;
    assert!(build_support::verify(root.path(), &lock, TARGET).is_err());
    Ok(())
}
#[test]
fn reject_wrong_target_source_features_and_untracked_files() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let (lock, receipt) = fixture(root.path())?;
    for (path, replacement) in [
        ("/target", json!("aarch64-unknown-linux-gnu")),
        ("/crt", json!("static")),
        ("/features/vp9", json!(true)),
        ("/sources/0/commit", json!("another-commit")),
        ("/files/0/path", json!("../outside.a")),
    ] {
        let mut changed = receipt.clone();
        *changed
            .pointer_mut(path)
            .ok_or_else(|| io::Error::other("fixture pointer"))? = replacement;
        write_receipt(root.path(), &changed)?;
        assert!(
            build_support::verify(root.path(), &lock, TARGET).is_err(),
            "{path}"
        );
    }
    write_receipt(root.path(), &receipt)?;
    fs::write(root.path().join("lib/extra.a"), b"undeclared")?;
    assert!(build_support::verify(root.path(), &lock, TARGET).is_err());
    Ok(())
}
#[cfg(unix)]
#[test]
fn reject_linked_prefix_components() -> io::Result<()> {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir()?;
    let (lock, _) = fixture(root.path())?;
    fs::rename(root.path().join("include"), root.path().join("saved"))?;
    symlink("saved", root.path().join("include"))?;
    assert!(build_support::verify(root.path(), &lock, TARGET).is_err());
    Ok(())
}
