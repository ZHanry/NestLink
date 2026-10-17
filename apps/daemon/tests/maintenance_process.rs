//! Actual subprocess owners. Fixtures kill only their own Child during failed
//! test teardown; product maintenance itself never forces a process to exit.
use nestlink_app_ipc::Client;
use std::{
    io,
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn start(args: &[&str], directory: &Path, control: Option<&Path>) -> Result<OwnedChild> {
    start_installed(args, directory, control, None)
}
fn start_installed(
    args: &[&str],
    directory: &Path,
    control: Option<&Path>,
    installation: Option<&Path>,
) -> Result<OwnedChild> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nestlink-daemon"));
    command.args(args).arg("--state-dir").arg(directory);
    if let Some(control) = control {
        command.arg("--control-dir").arg(control);
    }
    if let Some(installation) = installation {
        command.arg("--installation-dir").arg(installation);
    }
    Ok(OwnedChild(
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    ))
}
async fn status(child: &mut OwnedChild) -> Result<std::process::ExitStatus> {
    Ok(tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(status) = child.0.try_wait()? {
                return Ok::<_, io::Error>(status);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await??)
}
async fn connected(directory: &Path, child: &mut OwnedChild) -> Result<Client> {
    Ok(tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(client) = Client::connect(directory).await {
                return Ok(client);
            }
            if child.0.try_wait()?.is_some() {
                return Err(io::Error::other("daemon exited before IPC"));
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await??)
}
async fn ready(control: &Path, child: &mut OwnedChild) -> Result<serde_json::Value> {
    Ok(tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            match nestlink_platform_security::read_private(&control.join("ready.json"), 512) {
                Ok(bytes) => return serde_json::from_slice(&bytes).map_err(io::Error::other),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            if child.0.try_wait()?.is_some() {
                return Err(io::Error::other("maintenance exited before ready"));
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await??)
}
fn release(control: &Path, id: &str) -> Result {
    nestlink_platform_security::create_private(
        &control.join("release.json"),
        &serde_json::to_vec(&serde_json::json!({
            "schema_version": 1, "control_id": id, "action": "release"
        }))?,
    )?;
    Ok(())
}

#[tokio::test]
async fn actual_maintenance_exits_exact_authenticated_runtime_holds_admission_and_releases()
-> Result {
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join("state");
    let mut daemon = start(&[], &directory, None)?;
    let client = connected(&directory, &mut daemon).await?;
    let runtime = client.runtime_id().to_owned();
    let identity = std::fs::read(directory.join("installation-device.json"))?;
    drop(client);
    let id = nestlink_auth::random_id();
    let control = directory.join(format!("maintenance-{id}"));
    let mut owner = start(
        &[
            "maintenance",
            "--timeout-seconds",
            "10",
            "--hold-seconds",
            "30",
        ],
        &directory,
        Some(&control),
    )?;
    let receipt = ready(&control, &mut owner).await?;
    assert_eq!(receipt["stopped_runtime_id"], runtime);
    assert_eq!(receipt["control_id"], id);
    assert!(status(&mut daemon).await?.success());
    assert!(matches!(
        nestlink_local_ipc::LocalServer::bind(&directory).await,
        Err(nestlink_local_ipc::Error::Maintenance)
    ));
    assert!(matches!(
        nestlink_local_ipc::maintenance::DesktopLease::acquire(&directory),
        Err(nestlink_local_ipc::Error::Maintenance)
    ));
    assert_eq!(
        std::fs::read(directory.join("installation-device.json"))?,
        identity
    );
    release(&control, &id)?;
    assert!(status(&mut owner).await?.success());
    assert!(!directory.join("maintenance-incomplete.json").exists());
    let mut replacement = start(&[], &directory, None)?;
    let client = connected(&directory, &mut replacement).await?;
    assert_ne!(client.runtime_id(), runtime);
    drop(client);
    let mut shutdown = start(&["shutdown", "--timeout-seconds", "10"], &directory, None)?;
    assert!(status(&mut shutdown).await?.success());
    assert!(status(&mut replacement).await?.success());
    assert_eq!(
        std::fs::read(directory.join("installation-device.json"))?,
        identity
    );
    Ok(())
}

#[tokio::test]
async fn expired_controller_keeps_interrupted_installation_fenced_until_explicit_recovery() -> Result
{
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join("state");
    nestlink_local_ipc::initialize_directory(&directory)?;
    let id = nestlink_auth::random_id();
    let control = directory.join(format!("maintenance-{id}"));
    let mut owner = start(
        &[
            "maintenance",
            "--timeout-seconds",
            "2",
            "--hold-seconds",
            "1",
        ],
        &directory,
        Some(&control),
    )?;
    ready(&control, &mut owner).await?;
    assert!(!status(&mut owner).await?.success());
    assert!(directory.join("maintenance-incomplete.json").is_file());
    let mut refused = start(&[], &directory, None)?;
    assert!(!status(&mut refused).await?.success());
    assert!(!directory.join("installation-device.key").exists());
    let mut recovery = start(&["shutdown", "--timeout-seconds", "2"], &directory, None)?;
    assert!(status(&mut recovery).await?.success());
    assert!(!directory.join("maintenance-incomplete.json").exists());
    Ok(())
}

#[tokio::test]
async fn maintenance_waits_for_real_ui_lifetime_and_never_treats_missing_endpoint_as_exit() -> Result
{
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join("state");
    let desktop = nestlink_local_ipc::maintenance::DesktopLease::acquire(&directory)?;
    let id = nestlink_auth::random_id();
    let control = directory.join(format!("maintenance-{id}"));
    let mut owner = start(
        &[
            "maintenance",
            "--timeout-seconds",
            "1",
            "--hold-seconds",
            "2",
        ],
        &directory,
        Some(&control),
    )?;
    assert!(!status(&mut owner).await?.success());
    assert!(!control.join("ready.json").exists());
    assert!(directory.join("maintenance-incomplete.json").is_file());
    drop(desktop);
    let mut recovery = start(&["shutdown", "--timeout-seconds", "2"], &directory, None)?;
    assert!(status(&mut recovery).await?.success());
    Ok(())
}

#[tokio::test]
async fn abandoned_installation_releases_os_owners_but_keeps_both_fences_until_recovery() -> Result
{
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join("state");
    let installation = temporary.path().join("install");
    nestlink_local_ipc::initialize_directory(&installation)?;
    let payload = installation.join("versions/15.0.0-r1/nestlink-daemon");
    std::fs::create_dir_all(payload.parent().ok_or("missing fixture parent")?)?;
    std::fs::write(&payload, b"regular fixture only; never executed")?;
    nestlink_local_ipc::initialize_directory(&directory)?;
    let id = nestlink_auth::random_id();
    let control = directory.join(format!("maintenance-{id}"));
    let mut owner = start_installed(
        &[
            "maintenance",
            "--timeout-seconds",
            "2",
            "--hold-seconds",
            "30",
        ],
        &directory,
        Some(&control),
        Some(&installation),
    )?;
    let receipt = ready(&control, &mut owner).await?;
    assert_eq!(receipt["installation_recovery"], false);
    nestlink_platform_security::create_private(
        &control.join("release.json"),
        &serde_json::to_vec(&serde_json::json!({
            "schema_version": 1, "control_id": id, "action": "abandon"
        }))?,
    )?;
    assert!(status(&mut owner).await?.success());
    assert!(control.join("abandoned.json").is_file());
    assert!(directory.join("maintenance-incomplete.json").is_file());
    assert!(installation.join("installation-incomplete.json").is_file());
    assert!(matches!(
        nestlink_local_ipc::maintenance::DesktopLease::acquire(&directory),
        Err(nestlink_local_ipc::Error::Maintenance)
    ));
    assert!(matches!(
        nestlink_local_ipc::maintenance::InstallationStartup::acquire(&payload),
        Err(nestlink_local_ipc::Error::Maintenance)
    ));
    let recovery_id = nestlink_auth::random_id();
    let recovery_control = directory.join(format!("maintenance-{recovery_id}"));
    let mut recovery = start_installed(
        &[
            "maintenance",
            "--timeout-seconds",
            "2",
            "--hold-seconds",
            "30",
        ],
        &directory,
        Some(&recovery_control),
        Some(&installation),
    )?;
    let receipt = ready(&recovery_control, &mut recovery).await?;
    assert_eq!(receipt["installation_recovery"], true);
    release(&recovery_control, &recovery_id)?;
    assert!(status(&mut recovery).await?.success());
    assert!(!directory.join("maintenance-incomplete.json").exists());
    assert!(!installation.join("installation-incomplete.json").exists());
    let _startup = nestlink_local_ipc::maintenance::InstallationStartup::acquire(&payload)?;
    let _ui = nestlink_local_ipc::maintenance::DesktopLease::acquire(&directory)?;
    Ok(())
}
