//! Actual native Windows processes and the production pinned TLS path. These
//! checks do not create GPU resources or claim physical media acceptance.
use super::*;
use std::{
    os::windows::process::CommandExt,
    process::{Child, Command, Stdio},
};
type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const CHILD_DIRECTORY: &str = "NESTLINK_NATIVE_TLS_CHILD_DIRECTORY";
const EXPORTED_CONTENT: &str = "original retained native TLS process export";

use nestlink_platform_security::local_stream::process_handle_test_support as native_handle_fixture;
struct ChildOwner(Child);
impl Drop for ChildOwner {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn child_native_tls_process() -> TestResult {
    let Some(directory) = std::env::var_os(CHILD_DIRECTORY) else {
        return Ok(());
    };
    let mut client = LocalStream::connect(Path::new(&directory)).await?;
    client.verified_peer_process()?.check_current()?;
    client.send(&"native-child-ready").await?;
    let content = native_handle_fixture::read_file_once(client.receive::<u64>().await?)?;
    assert_eq!(content, EXPORTED_CONTENT);
    client.send(&content).await?;
    assert_eq!(client.receive::<String>().await?, "exit-original-child");
    Ok(())
}

#[tokio::test]
async fn original_native_tls_peer_is_the_actual_child_and_exit_retires_its_handle() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join("state");
    let daemon = LocalServer::bind(&directory).await?;
    let mut child = ChildOwner(
        Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "process_tests::child_native_tls_process",
                "--nocapture",
            ])
            .env(CHILD_DIRECTORY, &directory)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(0x0800_0000)
            .spawn()?,
    );
    let mut accepted = tokio::time::timeout(Duration::from_secs(5), async {
        daemon.accept().await?.authenticate().await
    })
    .await??;
    let original = accepted.verified_peer_process()?;
    assert_eq!(original.process_id(), child.0.id());
    assert_ne!(original.process_id(), std::process::id());
    assert_eq!(original.runtime_id(), daemon.runtime_id());
    assert_eq!(accepted.receive::<String>().await?, "native-child-ready");
    original.check_current()?;
    let target = original.export_target()?;
    let mut source = tempfile::NamedTempFile::new()?;
    std::io::Write::write_all(&mut source, EXPORTED_CONTENT.as_bytes())?;
    let source = std::fs::File::open(source.path())?;
    let remote = native_handle_fixture::duplicate_file(&source, &target)?;
    drop(source);
    accepted.send(&remote).await?;
    assert_eq!(accepted.receive::<String>().await?, EXPORTED_CONTENT);
    accepted.send(&"exit-original-child").await?;
    let status = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(status) = child.0.try_wait()? {
                return Ok::<_, io::Error>(status);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    assert!(status.success());
    assert!(original.check_current().is_err());
    assert!(target.check_current().is_err());
    let invoked = std::sync::atomic::AtomicBool::new(false);
    assert!(
        target
            .with_process_handle(|_| {
                invoked.store(true, std::sync::atomic::Ordering::Release);
                Ok(())
            })
            .is_err()
    );
    assert!(!invoked.load(std::sync::atomic::Ordering::Acquire));
    Ok(())
}

#[tokio::test]
async fn native_tls_drop_cancel_and_original_daemon_stop_fence_every_peer_clone() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join("state");
    let daemon = LocalServer::bind(&directory).await?;
    let open = async {
        let (client, server) = tokio::join!(LocalStream::connect(&directory), async {
            daemon.accept().await?.authenticate().await
        });
        Ok::<_, Error>((client?, server?))
    };
    let (client, accepted) = open.await?;
    let original = accepted.verified_peer_process()?;
    assert_eq!(original.process_id(), std::process::id());
    drop(accepted);
    assert!(original.check_current().is_err());
    drop(client);

    let (client, server) = tokio::join!(LocalStream::connect(&directory), async {
        daemon.accept().await?.authenticate().await
    });
    let (mut client, mut accepted) = (client?, server?);
    let original = accepted.verified_peer_process()?;
    client.stream.write_u8(0).await?;
    client.stream.flush().await?;
    assert!(
        tokio::time::timeout(Duration::from_millis(25), accepted.receive::<String>())
            .await
            .is_err()
    );
    assert!(original.check_current().is_err());

    let (client, server) = tokio::join!(LocalStream::connect(&directory), async {
        daemon.accept().await?.authenticate().await
    });
    let (_client, accepted) = (client?, server?);
    let original = accepted.verified_peer_process()?;
    let (_read, _write, owner) = accepted.into_duplex()?;
    drop(owner);
    assert!(original.check_current().is_err());

    let (client, server) = tokio::join!(LocalStream::connect(&directory), async {
        daemon.accept().await?.authenticate().await
    });
    let (_client, accepted) = (client?, server?);
    let original = accepted.verified_peer_process()?;
    daemon.stop();
    assert!(original.check_current().is_err());
    Ok(())
}

#[tokio::test]
async fn original_tcp_tls_compatibility_has_no_native_process_proof() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join("state");
    let daemon = LocalServer::bind(&directory).await?;
    let legacy = async {
        let endpoint = state::endpoint(&directory)?;
        let keys = state::identities(&directory, false)?;
        let mut tls =
            nestlink_transport_stream::tls::client_config(&keys.client, keys.server.fingerprint())
                .map_err(|_| Error::Authentication)?;
        tls.alpn_protocols = vec![ALPN.to_vec()];
        let socket = LocalTransport::connect_tcp(&endpoint).await?;
        let name = rustls::pki_types::ServerName::try_from("peer.nestlink.invalid")
            .map_err(|_| Error::Authentication)?;
        let stream = tokio_rustls::TlsConnector::from(Arc::new(tls))
            .connect(name, socket)
            .await?;
        Ok::<_, Error>(stream)
    };
    let (client, accepted) = tokio::join!(legacy, async {
        daemon.accept().await?.authenticate().await
    });
    let mut client = client?;
    let accepted = accepted?;
    assert!(matches!(
        accepted.verified_peer_process(),
        Err(Error::Authentication)
    ));
    let size = client.read_u32().await? as usize;
    assert!((1..=FRAME_BYTES).contains(&size));
    let mut bytes = vec![0; size];
    client.read_exact(&mut bytes).await?;
    let hello: Hello = serde_json::from_slice(&bytes)?;
    assert_eq!(hello.version, VERSION);
    assert_eq!(hello.runtime_id, daemon.runtime_id());
    Ok(())
}

#[tokio::test]
async fn new_client_reuses_original_tcp_tls_when_old_daemon_has_no_native_pipe() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join("state");
    let daemon = LocalServer::bind(&directory).await?;
    daemon.native.lock().await.stop_accepting();
    // Exercise the old daemon's actual TCP acceptor and exact TLS/Hello path;
    // the newer native accept branch is deliberately not part of this owner.
    let old_acceptor = async {
        PendingConnection {
            socket: LocalTransport::tcp(&daemon.listener).await?,
            acceptor: daemon.acceptor.clone(),
            runtime_id: daemon.runtime_id.clone(),
            stopped: daemon.stopped.subscribe(),
            slot: daemon
                .slots
                .clone()
                .try_acquire_owned()
                .map_err(|_| Error::Protocol)?,
        }
        .authenticate()
        .await
    };
    let (client, server) = tokio::join!(LocalStream::connect(&directory), old_acceptor);
    let (mut client, mut accepted) = (client?, server?);
    assert!(client.verified_peer_process().is_err());
    assert!(accepted.verified_peer_process().is_err());
    client.send(&"legacy-tls-only").await?;
    assert_eq!(accepted.receive::<String>().await?, "legacy-tls-only");
    Ok(())
}
