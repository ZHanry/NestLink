//! Exercises the built executable, OS key storage and actual HTTP listener.
use nestlink_platform_security::{create_private, new_private_directory};
use std::{
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[test]
fn binary_node_initialization_uses_a_fresh_private_identity_and_refuses_overwrite() -> Result {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use nestlink_identity::nodes::NodeIdentity;
    use nestlink_node::control::NodeConfig;
    use nestlink_protocol::api::NodeRegistration;
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join("node");
    let deployment = nestlink_auth::random_id();
    // Fixed, public test seed yields a valid base64url key beginning with '-'.
    let issuer = nestlink_identity::PermitSigner::from_seed([51; 32])
        .node_policy_signer()?
        .public_key();
    assert!(URL_SAFE_NO_PAD.encode(issuer).starts_with('-'));
    let binary = env!("CARGO_BIN_EXE_nestlink-server");
    let run = || {
        Command::new(binary)
            .args(["node-init", "--directory"])
            .arg(&directory)
            .args([
                "--deployment",
                &deployment,
                "--control-origin",
                "https://console.example.test",
                "--trusted-policy-issuer",
                &URL_SAFE_NO_PAD.encode(issuer),
                "--roles",
                "relay,edge",
            ])
            .output()
    };
    let initialized = run()?;
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    let registration: NodeRegistration = serde_json::from_slice(&initialized.stdout)?;
    let config = NodeConfig::load(&directory.join("node.toml"))?;
    assert_eq!(config.node_id, registration.id);
    assert_eq!(config.deployment_id, deployment);
    assert_eq!(config.trusted_policy_issuer, URL_SAFE_NO_PAD.encode(issuer));
    assert_eq!(config.roles, registration.roles);
    let seed = nestlink_platform_security::load_key(&config.identity_key_file)?;
    assert_eq!(
        URL_SAFE_NO_PAD.encode(NodeIdentity::from_seed(&seed).public_key()),
        registration.public_key
    );
    assert!(!run()?.status.success());
    assert_eq!(
        *nestlink_platform_security::load_key(&config.identity_key_file)?,
        *seed
    );
    Ok(())
}
#[test]
fn binary_backup_and_restore_are_offline_and_refuse_overwrite() -> Result {
    use nestlink_auth::{VaultKey, hash_password};
    use nestlink_server::config::ServerConfig;
    use nestlink_storage::Store;
    let temporary = tempfile::tempdir()?;
    // Migration admission keeps its stable lock in a protected parent.
    let private = temporary.path().join("private");
    new_private_directory(&private)?;
    let source = private.join("source");
    let binary = env!("CARGO_BIN_EXE_nestlink-server");
    let init = Command::new(binary)
        .args(["init", "--directory"])
        .arg(&source)
        .args(["--management-origin", "https://nestlink.example.test"])
        .output()?;
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let config_path = source.join("server.toml");
    let config = ServerConfig::load(&config_path)?;
    let account_password = private.join("account-secret");
    create_private(&account_password, b"binary-backup-account-password")?;
    let bootstrap = Command::new(binary)
        .args(["bootstrap", "--config"])
        .arg(&config_path)
        .args(["--username", "administrator", "--password-file"])
        .arg(&account_password)
        .output()?;
    assert!(
        bootstrap.status.success(),
        "{}",
        String::from_utf8_lossy(&bootstrap.stderr)
    );
    let vault_bytes = nestlink_platform_security::load_key(&config.vault_key_file)?;
    let vault = VaultKey::from_bytes(*vault_bytes);
    let mut original = Store::open_existing(&config.database, &config.deployment_id)?;
    let old_epoch = original.security_epoch()?;
    let dummy = hash_password("binary-backup-dummy-password")?;
    let login = original.login(
        "administrator",
        "binary-backup-account-password",
        None,
        1000,
        &vault,
        &dummy,
    )?;
    let password_file = private.join("backup-secret");
    create_private(&password_file, b"binary-backup-archive-password\r\n")?;
    let archive = private.join("deployment.nlbackup");
    let invoke_backup = || {
        Command::new(binary)
            .args(["backup", "--config"])
            .arg(&config_path)
            .arg("--output")
            .arg(&archive)
            .arg("--password-file")
            .arg(&password_file)
            .output()
    };
    let backup = invoke_backup()?;
    assert!(
        backup.status.success(),
        "{}",
        String::from_utf8_lossy(&backup.stderr)
    );
    assert!(!String::from_utf8_lossy(&backup.stdout).contains("binary-backup-archive-password"));
    let encrypted = std::fs::read(&archive)?;
    assert!(encrypted.starts_with(b"NL15BA01"));
    assert!(!invoke_backup()?.status.success());
    assert_eq!(std::fs::read(&archive)?, encrypted);
    let target = private.join("restored");
    let invoke_restore =
        |password: &std::path::Path, directory: &std::path::Path, expected: &str| {
            Command::new(binary)
                .arg("restore")
                .arg("--input")
                .arg(&archive)
                .arg("--directory")
                .arg(directory)
                .arg("--expected-deployment")
                .arg(expected)
                .arg("--password-file")
                .arg(password)
                .output()
        };
    let wrong_password = private.join("wrong-secret");
    create_private(&wrong_password, b"binary-backup-incorrect-password")?;
    assert!(
        !invoke_restore(&wrong_password, &target, &config.deployment_id)?
            .status
            .success()
    );
    assert!(!target.exists());
    assert!(
        !invoke_restore(&password_file, &target, &nestlink_auth::random_id())?
            .status
            .success()
    );
    assert!(!target.exists());
    let restore = invoke_restore(&password_file, &target, &config.deployment_id)?;
    assert!(
        restore.status.success(),
        "{}",
        String::from_utf8_lossy(&restore.stderr)
    );
    let restored_config = ServerConfig::load(&target.join("server.toml"))?;
    assert_eq!(restored_config.database, target.join("control.sqlite3"));
    assert_eq!(
        *nestlink_platform_security::load_key(&restored_config.vault_key_file)?,
        *vault_bytes
    );
    let restored = Store::open_existing(&restored_config.database, &config.deployment_id)?;
    assert_ne!(restored.security_epoch()?, old_epoch);
    assert!(
        restored
            .authenticate(login.access_token.expose(), 1001)
            .is_err()
    );
    assert!(
        original
            .authenticate(login.access_token.expose(), 1001)
            .is_ok()
    );
    assert!(
        !invoke_restore(&password_file, &source, &config.deployment_id)?
            .status
            .success()
    );
    assert_eq!(original.security_epoch()?, old_epoch);
    let check = Command::new(binary)
        .args(["check", "--config"])
        .arg(target.join("server.toml"))
        .output()?;
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
    Ok(())
}
#[tokio::test]
async fn initialized_binary_bootstraps_and_serves_real_http() -> Result {
    let temporary = tempfile::tempdir()?;
    let private = temporary.path().join("private");
    new_private_directory(&private)?;
    let directory = private.join("deployment");
    let reservation = TcpListener::bind("127.0.0.1:0").await?;
    let address = reservation.local_addr()?;
    let binary = env!("CARGO_BIN_EXE_nestlink-server");
    let init = Command::new(binary)
        .args(["init", "--directory"])
        .arg(&directory)
        .args([
            "--management-origin",
            &format!("http://{address}"),
            "--listen",
            &address.to_string(),
            "--allow-loopback-http",
        ])
        .output()?;
    assert!(
        init.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    let original_key = std::fs::read(directory.join("vault.key"))?;
    assert_eq!(
        nestlink_platform_security::load_key(&directory.join("vault.key"))?.len(),
        32
    );
    #[cfg(windows)]
    assert!(original_key.starts_with(b"NL15DP01"));
    let again = Command::new(binary)
        .args(["init", "--directory"])
        .arg(&directory)
        .args([
            "--management-origin",
            &format!("http://{address}"),
            "--allow-loopback-http",
        ])
        .output()?;
    assert!(!again.status.success());
    assert_eq!(std::fs::read(directory.join("vault.key"))?, original_key);
    let password = directory.join("bootstrap-secret");
    create_private(&password, b"binary-only-test-password")?;
    let config = directory.join("server.toml");
    let bootstrap = Command::new(binary)
        .args(["bootstrap", "--config"])
        .arg(&config)
        .args(["--username", "admin", "--password-file"])
        .arg(&password)
        .output()?;
    assert!(
        bootstrap.status.success(),
        "bootstrap failed: {}",
        String::from_utf8_lossy(&bootstrap.stderr)
    );
    assert!(!String::from_utf8_lossy(&bootstrap.stdout).contains("binary-only-test-password"));
    drop(reservation);
    let _child = Running(
        Command::new(binary)
            .args(["control", "--config"])
            .arg(&config)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let mut connected = None;
    for _ in 0..200 {
        if let Ok(stream) = TcpStream::connect(address).await {
            connected = Some(stream);
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mut stream = connected.ok_or("binary listener did not become ready")?;
    stream
        .write_all(b"GET /api/v3/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    let mut response = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(2),
        stream.take(262144).read_to_end(&mut response),
    )
    .await??;
    let response = String::from_utf8(response)?;
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.contains("\"product\":\"NestLink\""));
    assert!(response.contains("\"permit_issuer\":"));
    Ok(())
}
