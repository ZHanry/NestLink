//! Existing bounded native-tool execution with one extra gate requirement:
//! the original journal flock survives in the actual nft child across a helper
//! crash, so recovery cannot race a transaction still committing in the kernel.
use super::*;
use std::{os::unix::process::CommandExt, process::Stdio, time::Duration};
use tokio::{io::AsyncReadExt, process::Command};

pub(super) fn nft_tool() -> io::Result<PathBuf> {
    for directory in ["/usr/sbin", "/usr/bin", "/sbin", "/bin"] {
        let path = Path::new(directory).join("nft");
        if let Ok(path) = path.canonicalize() {
            let meta = path.metadata()?;
            if meta.is_file() && meta.uid() == 0 && meta.mode() & 0o022 == 0 { trusted_ancestors(path.parent().ok_or_else(|| invalid("nft parent missing"))?)?; return Ok(path); }
        }
    }
    Err(invalid("root-owned nftables component is unavailable"))
}
pub(super) async fn run(store: &Store, args: &[String]) -> io::Result<Vec<u8>> {
    let program = nft_tool()?;
    let inherited = store.lock.try_clone()?;
    let mut command = Command::new(&program);
    command.current_dir(program.parent().ok_or_else(|| invalid("nft parent missing"))?)
        .args(args).env_clear().env("LANG", "C.UTF-8").env("LC_ALL", "C.UTF-8")
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
    // SAFETY: the closure only performs the async-signal-safe fcntl syscall on
    // one live duplicated File owned by the Command closure. It allocates no
    // memory, obtains no locks and never changes another descriptor. Keeping
    // this exact open-file description across exec preserves its kernel flock.
    #[allow(unsafe_code)]
    unsafe { command.as_std_mut().pre_exec(move || {
        let _keep_original = &inherited;
        rustix::io::fcntl_setfd(&inherited, rustix::io::FdFlags::empty()).map_err(io::Error::from)
    }); }
    let mut child = command.spawn()?;
    let mut stdout = child.stdout.take().ok_or_else(|| invalid("nft stdout missing"))?.take(MAXIMUM_JSON + 1);
    let mut stderr = child.stderr.take().ok_or_else(|| invalid("nft stderr missing"))?.take(4097);
    let execution = async {
        let mut output = Vec::new(); let mut errors = Vec::new();
        let (read, diagnostic, status) = tokio::join!(stdout.read_to_end(&mut output), stderr.read_to_end(&mut errors), child.wait());
        read?; diagnostic?;
        if output.len() > MAXIMUM_JSON as usize || errors.len() > 4096 { return Err(invalid("nft output exceeded its bound")); }
        if !status?.success() { return Err(invalid(&format!("nft operation failed; original gate/journal retained: {}", String::from_utf8_lossy(&errors)))); }
        Ok(output)
    };
    let result = match tokio::time::timeout(Duration::from_secs(3), execution).await {
        Ok(result) => result,
        Err(_) => { let _ = child.kill().await; let _ = child.wait().await; Err(invalid("nft deadline expired; original child joined and journal retained")) },
    };
    // The Command's inherited copy is intentionally kept until this original
    // child has actually exited; no process-ID-only cleanup receipt is used.
    drop(command); result
}
