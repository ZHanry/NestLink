use super::{Result, io};
use std::{path::Path, process::Stdio, time::Duration};
use tokio::{io::AsyncReadExt, process::Command};

// A cold Windows PowerShell/CIM provider startup is part of the native NRPT
// operation. Bound that startup separately from the small Linux CLI budget;
// timeout still fails the operation and retains the recovery journal.
#[cfg(windows)]
const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
#[cfg(not(windows))]
const COMMAND_TIMEOUT: Duration = Duration::from_secs(3);

/// Bounded native execution. No shell command is accepted from a plan.
pub(super) async fn run(
    program: &Path,
    args: &[String],
    environment: Option<(&str, String)>,
) -> Result<Vec<u8>> {
    let mut command = Command::new(program);
    command.current_dir(
        program
            .parent()
            .ok_or_else(|| io::Error::other("OS tool parent missing"))?,
    );
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    // Administrative tools inherit no caller-controlled loader, D-Bus, pager
    // or PowerShell module search environment.
    command
        .env_clear()
        .env("LANG", "C.UTF-8")
        .env("LC_ALL", "C.UTF-8")
        .env("SYSTEMD_PAGER", "")
        .env("SYSTEMD_COLORS", "0");
    #[cfg(windows)]
    if let Some(windows) = program.ancestors().nth(4) {
        command.env("SystemRoot", windows).env("WINDIR", windows);
    }
    if let Some((name, value)) = environment {
        command.env(name, value);
    }
    #[cfg(windows)]
    {
        command.creation_flags(0x08000000);
    }
    let mut child = command.spawn().map_err(|error| {
        io::Error::other(format!(
            "cannot start OS DNS tool {}: {error}",
            program.display()
        ))
    })?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("missing OS tool stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("missing OS tool stderr"))?;
    let mut stdout = stdout.take(65_537);
    let mut stderr = stderr.take(4_097);
    // Keep bounded stage diagnostics when a native provider fails to finish.
    // A timeout must identify how far the trusted operation actually reached.
    let mut errors = Vec::new();
    let execution = async {
        let mut output = Vec::new();
        let (out, err, status) = tokio::join!(
            stdout.read_to_end(&mut output),
            stderr.read_to_end(&mut errors),
            child.wait()
        );
        out?;
        err?;
        if output.len() > 65_536 || errors.len() > 4_096 {
            return Err(io::Error::other("OS DNS tool output exceeded its bound").into());
        }
        if !status?.success() {
            return Err(io::Error::other(format!("OS DNS operation failed; administrator/root permission and required OS services are necessary: {}", String::from_utf8_lossy(&errors))).into());
        }
        Ok(output)
    };
    match tokio::time::timeout(COMMAND_TIMEOUT, execution).await {
        Ok(result) => result,
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            Err(io::Error::other(format!(
                "OS DNS command timed out; journal retained for recovery; native diagnostics: {}",
                String::from_utf8_lossy(&errors)
            ))
            .into())
        }
    }
}
