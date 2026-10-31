//! The mature distribution tool receives secrets through bounded private stdin.
//! Neither command arguments nor errors include key or QR/config contents.
use super::*;
use std::{os::unix::fs::MetadataExt, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};
fn tool(name: &str) -> Result<PathBuf> {
    if !matches!(name, "wg" | "qrencode") {
        return Err(io::Error::other("unsupported WireGuard component").into());
    }
    let path = Path::new("/usr/bin").join(name).canonicalize()?;
    for ancestor in path.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor)?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 || metadata.file_type().is_symlink()
        {
            return Err(io::Error::other("WireGuard tool and ancestors must remain root-owned and unmodifiable by ordinary users").into());
        }
    }
    if !path.is_file() {
        return Err(io::Error::other("root-owned WireGuard tool is not a regular file").into());
    }
    Ok(path)
}
pub(crate) async fn run(
    name: &str,
    args: &[&str],
    input: &[u8],
    maximum: u64,
) -> Result<Zeroizing<Vec<u8>>> {
    if input.len() > 4096 || maximum == 0 || maximum > 1_048_576 {
        return Err(io::Error::other("bounded WireGuard component input/output required").into());
    }
    let path = tool(name)?;
    let mut child = Command::new(&path)
        .args(args)
        .env_clear()
        .env("LANG", "C.UTF-8")
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("WireGuard component stdin missing"))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("WireGuard component stdout missing"))?
        .take(maximum + 1);
    let execution = async {
        let mut output = Zeroizing::new(Vec::new());
        let writing = async {
            stdin.write_all(input).await?;
            stdin.shutdown().await?;
            drop(stdin);
            Ok::<(), io::Error>(())
        };
        let (written, read, status) =
            tokio::join!(writing, stdout.read_to_end(&mut output), child.wait());
        written?;
        read?;
        if !status?.success() || output.len() as u64 > maximum {
            return Err(io::Error::other(
                "trusted WireGuard component failed or exceeded its output bound",
            )
            .into());
        }
        Ok(output)
    };
    match tokio::time::timeout(Duration::from_secs(3), execution).await {
        Ok(result) => result,
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            Err(io::Error::other("trusted WireGuard component timed out").into())
        }
    }
}
