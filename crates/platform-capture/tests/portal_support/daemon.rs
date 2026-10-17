use super::Result;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
#[derive(Clone, Copy)]
pub struct Target {
    pub node: u32,
    pub serial: u64,
}
pub struct Daemon {
    directory: tempfile::TempDir,
    child: Child,
}
impl Daemon {
    pub fn new() -> Result<Self> {
        let directory = tempfile::Builder::new()
            .prefix("nestlink-pw-owned-")
            .tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let config = directory.path().join("capture.conf");
        fs::write(&config, include_str!("../pipewire-owned.conf"))?;
        let log = fs::File::create(directory.path().join("daemon.log"))?;
        let child = Command::new("pipewire")
            .arg("--config")
            .arg(&config)
            .env("XDG_RUNTIME_DIR", directory.path())
            .env("PIPEWIRE_RUNTIME_DIR", directory.path())
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()?;
        let mut owned = Self { directory, child };
        let started = Instant::now();
        while !owned.socket().exists() {
            if owned.child.try_wait()?.is_some() || started.elapsed() > Duration::from_secs(3) {
                return Err(format!(
                    "owned PipeWire failed: {}",
                    fs::read_to_string(owned.directory.path().join("daemon.log"))?
                )
                .into());
            }
            thread::sleep(Duration::from_millis(5));
        }
        Ok(owned)
    }
    pub fn socket(&self) -> std::path::PathBuf {
        self.directory.path().join("nestlink-capture-fixture")
    }
    pub fn command(&self, binary: &str) -> Command {
        let mut command = Command::new(binary);
        command
            .env("XDG_RUNTIME_DIR", self.directory.path())
            .env("PIPEWIRE_RUNTIME_DIR", self.directory.path())
            .env("PIPEWIRE_REMOTE", "nestlink-capture-fixture");
        command
    }
    pub fn source(&self) -> Result<Target> {
        let output = self.run(self.command("pw-dump"))?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).into_owned().into());
        }
        let objects: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        objects
            .as_array()
            .ok_or("invalid dump")?
            .iter()
            .find_map(|v| {
                if v["info"]["props"]["node.name"] != "nestlink-owned-video" {
                    return None;
                }
                Some(Target {
                    node: u32::try_from(v["id"].as_u64()?).ok()?,
                    serial: v["info"]["props"]["object.serial"].as_u64()?,
                })
            })
            .ok_or_else(|| "owned source missing".into())
    }
    pub fn link(&self) -> Result {
        let started = Instant::now();
        loop {
            let mut command = self.command("pw-link");
            command.args([
                "nestlink-owned-video:capture_1",
                "nestlink-portal-capture:input_1",
            ]);
            let output = self.run(command)?;
            if output.status.success() {
                return Ok(());
            }
            if started.elapsed() > Duration::from_secs(3) {
                let mut inventory = self.command("pw-link");
                inventory.args(["-I", "-o", "-i"]);
                let ports = self.run(inventory)?;
                return Err(format!(
                    "fixture link failed: {}; ports: {}",
                    String::from_utf8_lossy(&output.stderr),
                    String::from_utf8_lossy(&ports.stdout)
                )
                .into());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
    pub fn run(&self, command: Command) -> Result<std::process::Output> {
        run_owned(self.directory.path(), command, Duration::from_secs(2))
    }
}
fn run_owned(
    directory: &std::path::Path,
    mut command: Command,
    budget: Duration,
) -> Result<std::process::Output> {
    let stdout = tempfile::NamedTempFile::new_in(directory)?;
    let stderr = tempfile::NamedTempFile::new_in(directory)?;
    let mut child = command
        .stdout(Stdio::from(stdout.reopen()?))
        .stderr(Stdio::from(stderr.reopen()?))
        .spawn()?;
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() > budget
            || stdout.as_file().metadata()?.len() > 4 * 1024 * 1024
            || stderr.as_file().metadata()?.len() > 65536
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err("owned PipeWire tool exceeded time/output budget".into());
        }
        thread::sleep(Duration::from_millis(5));
    };
    if stdout.as_file().metadata()?.len() > 4 * 1024 * 1024
        || stderr.as_file().metadata()?.len() > 65536
    {
        return Err("owned PipeWire tool exceeded output budget".into());
    }
    Ok(std::process::Output {
        status,
        stdout: fs::read(stdout.path())?,
        stderr: fs::read(stderr.path())?,
    })
}
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
