//! Actions-only process roles for the bounded network namespace experiment.
//! The file provider approves one real fixture file; production FileRead,
//! Session, endpoint proofs and QUIC own all wire and authorization behavior.
//! This is not target installation, media capture, NAT or multi-relay evidence.
#![cfg(target_os = "linux")]

use nestlink_auth::random_id;
use nestlink_identity::{
    InstallationIdentity, PermitSigner, VerifiedPermit, digest, verify_permit,
};
use nestlink_policy::PathSet;
use nestlink_protocol::{FileReadManifest, Path, Permission, PermitClaims, SCHEMA_VERSION};
use nestlink_remote::{
    RuntimeClock, SessionLifecycle, SessionSetup, TransportMode,
    files::{
        FileReadClient, FileReadConsent, FileReadDevice, FileReadServer, FileReadSource,
        FileReadVerifier, FileShutdown,
    },
};
use nestlink_session::{EndpointRole, Session, SessionBinding, StopReason};
use nestlink_transport_quic::{connect, connector, listener};
use nestlink_transport_stream::Channel;
use prost::Message;
use std::{
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom},
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};
use tokio::sync::watch;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const PORT: u16 = 4433;
const ROOT: &str = "a1000000-1111-4111-8111-111111111111";
const TRANSFER: &str = "a2000000-1111-4111-8111-111111111111";

fn fixture(require_namespace: bool) -> Result<PathBuf> {
    assert_eq!(std::env::var("GITHUB_ACTIONS")?.as_str(), "true");
    assert_eq!(
        std::env::var("RUNNER_ENVIRONMENT")?.as_str(),
        "github-hosted"
    );
    assert_eq!(
        std::env::var("GITHUB_REPOSITORY")?.as_str(),
        "ZHanry/NestLink"
    );
    let root = PathBuf::from(std::env::var("NESTLINK_NETWORK_FIXTURE")?).canonicalize()?;
    let temporary = PathBuf::from(std::env::var("RUNNER_TEMP")?).canonicalize()?;
    assert!(root.starts_with(&temporary) && root != temporary);
    if require_namespace {
        let actual = fs::read_link("/proc/self/ns/net")?;
        // The ordinary runner token cannot inspect root-owned PID 1 namespace
        // links on hardened hosted runners. The orchestrator records its own
        // kernel namespace before setpriv and verifies both created namespaces.
        let runner = std::env::var("NESTLINK_NETWORK_RUNNER_NAMESPACE")?;
        assert!(runner.starts_with("net:[") && runner.ends_with(']'));
        assert_ne!(actual.to_string_lossy(), runner);
        println!(
            "NESTLINK_NETWORK namespace={actual:?} pid={}",
            std::process::id()
        );
        let status = fs::read_to_string("/proc/self/status")?;
        let uid = status
            .lines()
            .find(|line| line.starts_with("Uid:"))
            .ok_or("missing uid")?;
        assert_ne!(uid.split_whitespace().nth(1), Some("0"));
        assert_ne!(uid.split_whitespace().nth(2), Some("0"));
        println!("NESTLINK_NETWORK {uid}");
    }
    Ok(root)
}

fn identity(root: &std::path::Path, role: &str) -> Result<InstallationIdentity> {
    let mut seed: [u8; 32] = fs::read(root.join(format!("{role}.seed")))?
        .try_into()
        .map_err(|_| "invalid fixture seed")?;
    Ok(InstallationIdentity::from_seed_zeroizing(&mut seed))
}

fn key(root: &std::path::Path, role: &str) -> Result<[u8; 32]> {
    fs::read(root.join(format!("{role}.public")))?
        .try_into()
        .map_err(|_| "invalid public key".into())
}

fn mark(root: &std::path::Path, name: &str) -> Result {
    fs::write(root.join(format!("{name}.pending")), b"observed\n")?;
    fs::rename(root.join(format!("{name}.pending")), root.join(name))?;
    println!("NESTLINK_NETWORK event={name}");
    Ok(())
}

async fn wait_mark(root: &std::path::Path, name: &str, deadline: tokio::time::Instant) -> Result {
    tokio::time::timeout_at(deadline, async {
        while !root.join(name).is_file() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    Ok(())
}

fn business_deadline(channels: &nestlink_remote::ChannelRuntime) -> Result<tokio::time::Instant> {
    // Keep the original 15-second permit. Do not let orchestration waits eat
    // the four seconds reserved for actual transport and file-worker cleanup.
    let remaining = channels.lease_control().remaining()?;
    let budget = remaining
        .checked_sub(Duration::from_secs(4))
        .ok_or("insufficient permit time for cleanup")?
        .min(Duration::from_secs(6));
    if budget < Duration::from_secs(2) {
        return Err("insufficient business experiment budget".into());
    }
    println!(
        "NESTLINK_NETWORK lease_remaining_ms={} business_budget_ms={} cleanup_reserve_ms=4000",
        remaining.as_millis(),
        budget.as_millis()
    );
    Ok(tokio::time::Instant::now() + budget)
}

fn permit(root: &std::path::Path) -> Result<VerifiedPermit> {
    Ok(verify_permit(
        &fs::read(root.join("permit.bin"))?,
        &key(root, "issuer")?,
    )?)
}

fn setup(
    permit: VerifiedPermit,
    role: EndpointRole,
    stop: watch::Receiver<Option<StopReason>>,
) -> Result<SessionSetup> {
    let c = permit.claims();
    let binding = SessionBinding {
        media: None,
        deployment_id: c.deployment_id.clone(),
        security_epoch: c.security_epoch,
        session_id: c.session_id.clone(),
        account_id: c.account_id.clone(),
        controller_device_id: c.controller_device_id.clone(),
        host_device_id: c.host_device_id.clone(),
        controller_key_sha256: c
            .controller_key_sha256
            .clone()
            .try_into()
            .map_err(|_| "controller digest")?,
        host_key_sha256: c
            .host_key_sha256
            .clone()
            .try_into()
            .map_err(|_| "host digest")?,
        resource_id: c.resource_id.clone(),
        policy_revision: c.policy_revision,
        connection_generation: c.connection_generation,
        capability_sha256: c
            .capability_sha256
            .clone()
            .try_into()
            .map_err(|_| "capability digest")?,
        granted_permissions: vec![Permission::View, Permission::FileRead],
        supported_capabilities: vec!["vp8".into()],
        local_paths: PathSet::DIRECT,
    };
    let clock = RuntimeClock::default();
    let now = clock.sample()?;
    Ok(SessionSetup {
        session: Session::activate(permit, binding, Path::Direct, now.monotonic_ms, now)?,
        path: Path::Direct,
        role,
        clock,
        lifecycle: SessionLifecycle::new(stop),
    })
}

#[test]
#[ignore = "R02: invoked only by the GitHub-hosted network experiment runner"]
fn prepare_fixture() -> Result {
    let root = fixture(false)?;
    let controller = identity(&root, "controller")?;
    let host = identity(&root, "host")?;
    fs::write(root.join("controller.public"), controller.public_key())?;
    fs::write(root.join("host.public"), host.public_key())?;
    let now = RuntimeClock::default().sample()?.unix_ms;
    let claims = PermitClaims {
        schema_version: SCHEMA_VERSION,
        deployment_id: random_id(),
        security_epoch: 1,
        session_id: random_id(),
        account_id: random_id(),
        controller_device_id: random_id(),
        host_device_id: random_id(),
        controller_key_sha256: controller.fingerprint().to_vec(),
        host_key_sha256: host.fingerprint().to_vec(),
        resource_id: random_id(),
        permissions: vec![Permission::View as i32, Permission::FileRead as i32],
        paths: vec![Path::Direct as i32],
        policy_revision: 1,
        connection_generation: 1,
        lease_sequence: 1,
        issued_at_unix_ms: now,
        expires_at_unix_ms: now + 15_000,
        capability_sha256: digest(b"network-socket-fixture-vp8").to_vec(),
        required_capabilities: vec!["vp8".into()],
        media_format_version: 0,
        media_formats: Vec::new(),
        media_format_sha256: Vec::new(),
    };
    let signer = PermitSigner::generate();
    fs::write(root.join("issuer.public"), signer.public_key())?;
    fs::write(
        root.join("permit.bin"),
        signer.sign(&claims)?.encode_to_vec(),
    )?;
    println!("NESTLINK_NETWORK fixture=prepared lease_ms=15000");
    Ok(())
}

// This thin fixture adapter grants one immutable, runner-generated file. The
// production FileRead worker owns requests, replay/offset checks and disclosure.
struct ApprovedFile(PathBuf);
struct Source {
    file: File,
    consent: Arc<AtomicBool>,
}
impl FileReadDevice for ApprovedFile {
    fn open(&mut self, root: &str, relative_path: &str) -> io::Result<Box<dyn FileReadSource>> {
        if root != ROOT || relative_path != "payload.bin" {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unapproved fixture file",
            ));
        }
        Ok(Box::new(Source {
            file: File::open(&self.0)?,
            consent: Arc::new(AtomicBool::new(true)),
        }))
    }
}
impl FileReadSource for Source {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        self.consent.clone()
    }
    fn describe(
        &mut self,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<FileReadManifest> {
        authorized()?;
        let size = self.file.metadata()?.len();
        if size > 1_048_576 {
            return Err(io::Error::other("fixture file budget exceeded"));
        }
        self.file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        self.file.by_ref().take(size + 1).read_to_end(&mut bytes)?;
        authorized()?;
        if bytes.len() as u64 != size {
            return Err(io::Error::other("fixture changed"));
        }
        Ok(FileReadManifest {
            size,
            sha256: digest(&bytes).to_vec(),
            offset: 0,
        })
    }
    fn read_chunk(
        &mut self,
        offset: u64,
        maximum: usize,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Vec<u8>> {
        authorized()?;
        let size = self.file.metadata()?.len();
        let remaining = size
            .checked_sub(offset)
            .ok_or_else(|| io::Error::other("offset exceeds file"))?;
        let length = remaining.min(maximum.min(65_536) as u64) as usize;
        let mut bytes = vec![0; length];
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.read_exact(&mut bytes)?;
        authorized()?;
        Ok(bytes)
    }
    fn verify(
        &mut self,
        original: &FileReadManifest,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        if self.describe(authorized)? != *original {
            return Err(io::Error::other("fixture changed during read"));
        }
        Ok(())
    }
}

#[tokio::test]
#[ignore = "R02: requires the owned host network namespace and Actions fixture"]
async fn host_process() -> Result {
    let root = fixture(true)?;
    let host = identity(&root, "host")?;
    let controller_key = key(&root, "controller")?;
    let endpoint = listener(
        ([10, 201, 0, 2], PORT).into(),
        &host,
        digest(&controller_key),
    )?;
    mark(&root, "host-ready")?;
    if std::env::var("NESTLINK_NETWORK_CASE")? == "blackhole" {
        match tokio::time::timeout(Duration::from_secs(3), endpoint.accept()).await {
            Err(_) => {
                // This is a distinct observed failure phase, not a completed
                // handshake. The runner separately requires captured Initials.
                mark(&root, "host-no-incoming")?;
            }
            Ok(None) => return Err("blackhole listener unexpectedly ended".into()),
            Ok(Some(incoming)) => {
                let result = tokio::time::timeout(Duration::from_secs(3), incoming).await;
                assert!(
                    !matches!(result, Ok(Ok(_))),
                    "blackholed QUIC unexpectedly completed"
                );
                println!("NESTLINK_NETWORK expected_handshake_failure={result:?}");
                mark(&root, "host-handshake-rejected")?;
            }
        }
        endpoint.close(0_u32.into(), b"expected blackhole complete");
        tokio::time::timeout(Duration::from_secs(4), endpoint.wait_idle()).await?;
        mark(&root, "host-finished")?;
        return Ok(());
    }
    let incoming = tokio::time::timeout(Duration::from_secs(4), endpoint.accept())
        .await?
        .ok_or("listener ended")?;
    let connection = tokio::time::timeout(Duration::from_secs(3), incoming).await??;
    let peer_close_case = std::env::var("NESTLINK_NETWORK_CASE")? == "peer-close";
    let close_observer = peer_close_case.then(|| connection.clone());
    let (stop, stopped) = watch::channel(None);
    let mut channels = nestlink_remote::quic::authorize(
        connection,
        Some(endpoint),
        setup(permit(&root)?, EndpointRole::Host, stopped)?,
        &host,
        &controller_key,
    )
    .await?;
    assert_eq!(channels.mode(), TransportMode::QuicStreamsAndDatagrams);
    let deadline = business_deadline(&channels)?;
    mark(&root, "host-authorized")?;
    let mut worker =
        FileReadServer::start(&mut channels, 1, ApprovedFile(root.join("payload.bin")))?;
    let stop_root = root.clone();
    // Keep the lifecycle sender alive through cleanup. The task's completion
    // is an orchestration fact, not an independent revocation signal.
    let stop_signal = stop.clone();
    let stop_task = tokio::spawn(async move {
        wait_mark(&stop_root, "host-stop", deadline).await?;
        let _ = stop_signal.send(Some(StopReason::ExplicitExit));
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    assert!(
        tokio::time::timeout_at(deadline, channels.receive())
            .await?
            .is_err()
    );
    if let Some(observer) = close_observer {
        let close = tokio::time::timeout_at(deadline, observer.closed()).await?;
        assert!(
            matches!(close, quinn::ConnectionError::ApplicationClosed(ref application)
                if application.error_code == quinn::VarInt::from_u32(0)),
            "expected the controller's actual code-0 application close: {close:?}"
        );
        println!("NESTLINK_NETWORK peer_application_close={close:?}");
    }
    let report = tokio::time::timeout(Duration::from_secs(3), channels.wait_stopped()).await??;
    if peer_close_case {
        // An unisolated peer ExplicitExit is intentionally fail-closed. This
        // separate case checks the exact production code-0 -> Revoked mapping.
        assert_eq!(report.reason, StopReason::Revoked);
        mark(&root, "host-peer-close-observed")?;
    } else {
        // The driver isolates teardown only after actual file/RPC assertions.
        // No peer close may race this independently requested local exit.
        assert_eq!(report.reason, StopReason::ExplicitExit);
    }
    assert_eq!(
        tokio::time::timeout(
            Duration::from_secs(1),
            worker.shutdown(StopReason::ExplicitExit)
        )
        .await??,
        FileShutdown::Finished
    );
    assert!(worker.monitor().status().finished);
    assert!(!worker.monitor().status().cleanup_timed_out);
    stop_task.await??;
    drop(stop);
    println!(
        "NESTLINK_NETWORK stopped={report:?} file_worker={:?}",
        worker.monitor().status()
    );
    assert!(
        channels
            .send(Channel::Video, b"forbidden after stop")
            .await
            .is_err()
    );
    mark(&root, "host-finished")?;
    Ok(())
}

#[tokio::test]
#[ignore = "R02: requires the owned client network namespace and Actions fixture"]
async fn client_process() -> Result {
    let root = fixture(true)?;
    let controller = identity(&root, "controller")?;
    let host_key = key(&root, "host")?;
    let endpoint = connector(([10, 201, 0, 1], 0).into(), &controller, digest(&host_key))?;
    let started = Instant::now();
    let connected = connect(
        &endpoint,
        ([10, 201, 0, 2], PORT).into(),
        Duration::from_millis(1800),
    )
    .await;
    if std::env::var("NESTLINK_NETWORK_CASE")? == "blackhole" {
        assert!(connected.is_err(), "blackholed client connected");
        assert!(
            started.elapsed() >= Duration::from_secs(1),
            "failure preceded the injected packet loss"
        );
        println!(
            "NESTLINK_NETWORK expected_connect_failure={connected:?} elapsed_ms={}",
            started.elapsed().as_millis()
        );
        endpoint.close(0_u32.into(), b"expected blackhole complete");
        tokio::time::timeout(Duration::from_secs(4), endpoint.wait_idle()).await?;
        mark(&root, "client-blackhole-rejected")?;
        mark(&root, "client-finished")?;
        return Ok(());
    }
    let connection = connected?;
    let peer_close =
        (std::env::var("NESTLINK_NETWORK_CASE")? == "peer-close").then(|| connection.clone());
    let (stop, stopped) = watch::channel(None);
    let mut channels = nestlink_remote::quic::authorize(
        connection,
        Some(endpoint),
        setup(permit(&root)?, EndpointRole::Controller, stopped)?,
        &controller,
        &host_key,
    )
    .await?;
    assert_eq!(channels.mode(), TransportMode::QuicStreamsAndDatagrams);
    let deadline = business_deadline(&channels)?;
    mark(&root, "client-authorized")?;
    assert!(
        channels
            .send(Channel::Input, b"permission must reject before enqueue")
            .await
            .is_err()
    );
    mark(&root, "ungranted-input-rejected")?;
    let mut client = FileReadClient::attach(&mut channels, 1)?;
    let expected: [u8; 32] = fs::read(root.join("payload.sha256"))?
        .try_into()
        .map_err(|_| "payload digest")?;
    let mut download = tokio::time::timeout_at(
        deadline,
        client.open(TRANSFER, ROOT, "payload.bin", 0, Some(expected)),
    )
    .await??;
    let mut verifier = FileReadVerifier::new(download.manifest().clone())?;
    let first = tokio::time::timeout_at(deadline, client.next(&mut download))
        .await??
        .ok_or("file unexpectedly empty")?;
    verifier.accept(&first)?;
    let mut received = first.data;
    mark(&root, "client-first-chunk")?;
    if std::env::var("NESTLINK_NETWORK_CASE")? == "cancel" {
        wait_mark(&root, "fault-installed", deadline).await?;
        assert!(
            deadline.saturating_duration_since(tokio::time::Instant::now())
                >= Duration::from_secs(2),
            "insufficient cancellation budget"
        );
        {
            let next = client.next(&mut download);
            tokio::pin!(next);
            assert!(
                tokio::time::timeout(Duration::from_millis(120), &mut next)
                    .await
                    .is_err(),
                "blackholed next chunk did not block"
            );
            mark(&root, "client-next-blocked")?;
            // Preserve the proved one-way RPC blackhole before the driver
            // isolates reverse teardown traffic. A peer code-0 close must not
            // win over the host's separately requested local cancellation.
            wait_mark(&root, "teardown-isolated", deadline).await?;
            assert!(
                deadline.saturating_duration_since(tokio::time::Instant::now())
                    >= Duration::from_secs(1),
                "insufficient local-stop budget after teardown isolation"
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(1), &mut next)
                    .await
                    .is_err(),
                "the pending RPC completed before local cancellation"
            );
            let cancelling = Instant::now();
            stop.send(Some(StopReason::ExplicitExit))?;
            assert!(
                tokio::time::timeout(Duration::from_secs(1), &mut next)
                    .await?
                    .is_err()
            );
            println!(
                "NESTLINK_NETWORK cancel_elapsed_ms={}",
                cancelling.elapsed().as_millis()
            );
        }
        let report =
            tokio::time::timeout(Duration::from_secs(3), channels.wait_stopped()).await??;
        assert_eq!(report.reason, StopReason::ExplicitExit);
        assert!(
            channels
                .send(Channel::Video, b"stale after cancellation")
                .await
                .is_err()
        );
        println!(
            "NESTLINK_NETWORK cancelled={report:?} partial_file_bytes={}",
            received.len()
        );
        mark(&root, "client-cancelled")?;
    } else {
        while let Some(chunk) =
            tokio::time::timeout_at(deadline, client.next(&mut download)).await??
        {
            verifier.accept(&chunk)?;
            received.extend_from_slice(&chunk.data);
        }
        verifier.finish()?;
        assert_eq!(digest(&received), expected);
        assert_eq!(received.len(), 262_144);
        client.retire()?;
        fs::write(root.join("received.bin"), &received)?;
        println!("NESTLINK_NETWORK verified_file_bytes={}", received.len());
        mark(&root, "client-complete")?;
        if std::env::var("NESTLINK_NETWORK_CASE")? != "peer-close" {
            wait_mark(&root, "teardown-isolated", deadline).await?;
        }
        if let Some(connection) = peer_close {
            // Put the actual peer CONNECTION_CLOSE on the transport before
            // retiring local I/O tasks can finish proof/business streams.
            // Otherwise the host can see their EOF and close itself first.
            // No await separates this from the local ExplicitExit request.
            connection.close(0_u32.into(), b"owned peer-close experiment");
            println!("NESTLINK_NETWORK requested_peer_application_close_code=0");
        }
        let report = tokio::time::timeout(
            Duration::from_secs(3),
            channels.shutdown(StopReason::ExplicitExit),
        )
        .await??;
        assert_eq!(report.reason, StopReason::ExplicitExit);
        println!("NESTLINK_NETWORK completed_local_exit={report:?}");
    }
    mark(&root, "client-finished")?;
    Ok(())
}
