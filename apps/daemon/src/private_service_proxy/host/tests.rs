//! Actual authoritative management and production host command lifecycle.
use super::*;
use clap::Parser;
use nestlink_auth::{Secret, VaultKey, random_id};
use nestlink_identity::PermitSigner;
use nestlink_protocol::{api::*, services::private::*, spaces::*};
use nestlink_sdk::DeploymentTrust;
use nestlink_server::{AppState, router};
use nestlink_storage::Store;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, UdpSocket}};

struct Task<T>(Option<tokio::task::JoinHandle<T>>);
impl<T> Task<T> {
    fn new(task: tokio::task::JoinHandle<T>) -> Self { Self(Some(task)) }
    async fn join(&mut self) -> Result<T> {
        let result = self.0.as_mut().ok_or("test task was not retained")?.await;
        self.0.take();
        Ok(result?)
    }
}
impl<T> Drop for Task<T> {
    fn drop(&mut self) { if let Some(task) = self.0.take() { task.abort(); } }
}
struct Fixture {
    sdk: Arc<Sdk>, host: Arc<DeviceIdentity>, consumer: DeviceIdentity,
    service: ServiceView, space: String, directory: PathBuf,
    _temporary: tempfile::TempDir, _server: Task<io::Result<()>>,
}
impl Fixture {
    async fn new() -> Result<Self> {
        let deployment = random_id();
        let signer = PermitSigner::generate();
        let issuer = signer.public_key();
        let mut store = Store::in_memory(&deployment)?;
        const PASSWORD: &str = "daemon-private-host-real-management-test";
        store.bootstrap_admin("admin", PASSWORD)?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("http://{}", listener.local_addr()?);
        let app = router(AppState::new(store, VaultKey::from_bytes([127;32]), signer, origin.clone(), false)?);
        let server = Task::new(tokio::spawn(async move {
            axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await
        }));
        let mut sdk = Sdk::connect(&origin, DeploymentTrust { deployment_id: deployment, permit_issuer: issuer }, true).await?;
        sdk.login("admin".into(), Secret::from_text(PASSWORD.into()), None).await?;
        let host = Arc::new(DeviceIdentity::generate());
        let consumer = DeviceIdentity::generate();
        for (device, name) in [(&*host, "daemon-host"), (&consumer, "explicit-consumer")] {
            sdk.enroll(device, name.into(), "linux-x11".into(), vec!["host".into(), "vp8".into()], "direct_only".into()).await?;
        }
        let mut space = sdk.create_space(SpaceCreateRequest { name: "daemon host scope".into() }).await?;
        for device in [&host.device_id, &consumer.device_id] {
            space = sdk.join_space_device(&space.space_id, SpaceDeviceJoin {
                expected_revision: space.revision, expected_membership_epoch: 0, installation_id: device.clone(),
            }).await?;
        }
        let service = sdk.create_service(&ServiceCreate { id: random_id(), definition: ServiceDefinition {
            name: "explicit daemon target".into(), host_device_id: host.device_id.clone(), edge_node_id: String::new(),
            requested_ingress: ServiceIngress::Tcp { port: 29100 }, allowed_sources: vec![],
            limits: ServiceLimits { maximum_connections: 4, bytes_per_second: 65536, maximum_bytes: 8192, idle_timeout_seconds: 5 },
        }}).await?;
        let temporary = tempfile::tempdir()?;
        let directory = temporary.path().join("private");
        nestlink_platform_security::new_private_directory(&directory)?;
        // Only the lifecycle witness is synthetic. All login/approval/ACL/grant
        // authorization above and below goes to the real management router.
        nestlink_platform_security::create_private(&directory.join("remember-login.json"), b"true")?;
        nestlink_platform_security::create_private(&directory.join("management-login.enc"), b"original test lifecycle witness")?;
        Ok(Self { sdk: Arc::new(sdk), host, consumer, service, space: space.space_id, directory, _temporary: temporary, _server: server })
    }
    fn args(&self, target: SocketAddr, seconds: u64) -> Result<HostArgs> {
        Ok(HostArgs { service: self.service.id.clone(), space: self.space.clone(), target, protocol: Protocol::Tcp,
            listen: "127.0.0.1:0".parse()?, advertised_ip: "127.0.0.1".parse()?, relay_private_prefixes: vec![], allow_loopback_relay: false,
            access_mode: AccessMode::Private, private_maximum_bytes: 8192, public_maximum_bytes: 0,
            approval_seconds: seconds, approve_target: true, backend_server_name: None, backend_ca_der: vec![] })
    }
    async fn exposure(&self) -> Result<ServiceExposureView> {
        Ok(tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                if let Some(view) = self.sdk.service_exposure(&self.service.id).await? { break Ok::<_, SdkError>(view); }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await??)
    }
    async fn grant(&self, exposure: &ServiceExposureView) -> Result<()> {
        self.sdk.grant_private_service(&self.service.id, PrivateServiceAclUpdate {
            expected_exposure_revision: exposure.revision,
            subject: PrivateServiceSubject::Installation { installation_id: self.consumer.device_id.clone() },
            expires_at_unix_ms: wall_ms()? + 60000,
        }).await?;
        Ok(())
    }
    async fn ready(&self) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let page = self.sdk.private_services(&self.consumer.device_id, None, 10).await?;
                if page.entries.iter().any(|entry| entry.service.id == self.service.id && entry.availability == PrivateServiceAvailability::Ready) { break Ok::<_, SdkError>(()); }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await??;
        Ok(())
    }
}

#[test]
fn host_cli_requires_explicit_local_approval_and_numeric_target() -> Result<()> {
    let base = ["nestlink-daemon", "private-service-proxy", "--state-dir", "private", "host",
        "--service", "00000000-0000-4000-8000-000000000001", "--space", "00000000-0000-4000-8000-000000000002",
        "--target", "127.0.0.1:8080", "--protocol", "tcp", "--listen", "0.0.0.0:0", "--advertised-ip", "192.0.2.2",
        "--access-mode", "private", "--private-maximum-bytes", "4096", "--public-maximum-bytes", "0", "--approval-seconds", "60"];
    assert!(crate::Args::try_parse_from(base).is_err());
    let mut approved = base.to_vec(); approved.push("--approve-target");
    assert!(crate::Args::try_parse_from(&approved).is_ok());
    let target = approved.iter().position(|value| *value == "127.0.0.1:8080").ok_or("target argument missing")?;
    approved[target] = "localhost:8080";
    assert!(crate::Args::try_parse_from(&approved).is_err());
    Ok(())
}

#[tokio::test]
async fn host_command_preserves_original_service_on_budget_and_tls_denial() -> Result<()> {
    let f = Fixture::new().await?;
    let mut args = f.args("127.0.0.1:8080".parse()?, 60)?;
    args.private_maximum_bytes = 8193;
    let guard = SessionGuard::new(f.directory.clone(), session_snapshot(&f.directory)?, &f.sdk, 60)?;
    assert!(start(&args, &f.sdk, f.host.clone(), &guard).await.is_err());
    args.private_maximum_bytes = 8192;
    args.public_maximum_bytes = 1;
    assert!(args.validate().is_err());
    args.public_maximum_bytes = 0;
    args.protocol = Protocol::Https;
    assert!(args.validate().is_err());
    let invalid_ca = f.directory.join("invalid-ca.der");
    nestlink_platform_security::create_private(&invalid_ca, b"invalid DER")?;
    args.backend_server_name = Some("backend.example.test".into()); args.backend_ca_der = vec![invalid_ca];
    assert!(args.backend_tls().is_err());
    let current = f.sdk.service(&f.service.id).await?;
    assert_eq!(current.revision, f.service.revision);
    assert_eq!(current.approval, ServiceApprovalState::Pending);
    assert!(f.sdk.service_exposure(&f.service.id).await?.is_none());
    assert!(!f.directory.join("private-service-usage").try_exists()?);
    Ok(())
}

#[tokio::test]
async fn host_command_real_bytes_no_automatic_acl_and_login_change_joins_original_target() -> Result<()> {
    let f = Fixture::new().await?;
    let backend = TcpListener::bind("127.0.0.1:0").await?;
    let args = f.args(backend.local_addr()?, 60)?;
    let mut target = Task::new(tokio::spawn(async move {
        let (mut stream, _) = backend.accept().await?;
        let mut request = [0;4]; stream.read_exact(&mut request).await?; assert_eq!(&request, b"ping");
        stream.write_all(b"pong").await?;
        let mut probe = [0;1]; assert_eq!(stream.read(&mut probe).await?, 0, "login change must close the original backend");
        Ok::<_, io::Error>(())
    }));
    let mut command = Task::new(tokio::spawn(run(args, f.sdk.clone(), f.host.clone(), f.directory.clone(), session_snapshot(&f.directory)?)));
    let exposure = f.exposure().await?;
    assert_eq!(exposure.service_revision, f.service.revision + 1);
    assert_eq!(exposure.private_maximum_bytes, 8192);
    assert_eq!(exposure.public_maximum_bytes, 0);
    assert!(f.sdk.private_services(&f.consumer.device_id, None, 10).await?.entries.is_empty(), "hosting must not grant a consumer ACL");
    f.grant(&exposure).await?; f.ready().await?;
    let lease = f.sdk.request_private_service(&f.service.id, PrivateServiceAccessRequest {
        request_id: random_id(), consumer_device_id: f.consumer.device_id.clone(),
        expected_service_revision: exposure.service_revision, expected_exposure_revision: exposure.revision, maximum_bytes: 1024,
        route: PrivateServiceRouteRequest::Direct,
    }).await?;
    let address: SocketAddr = lease.lease().claims().edge_service_address.parse()?;
    let mut connection = f.sdk.connect_private_service(&f.consumer, lease).await?;
    connection.stream()?.write_all(b"ping").await?;
    let mut reply = [0;4]; tokio::time::timeout(Duration::from_secs(3), connection.stream()?.read_exact(&mut reply)).await??;
    assert_eq!(&reply, b"pong");
    nestlink_platform_security::replace_private_metadata(&f.directory.join("management-login.enc"), b"changed test lifecycle witness")?;
    assert!(tokio::time::timeout(Duration::from_secs(10), command.join()).await??.is_err(), "changed login must produce an error after actual host cleanup");
    tokio::time::timeout(Duration::from_secs(3), target.join()).await???;
    connection.close().await?;
    let rebound = UdpSocket::bind(address).await?; drop(rebound);
    assert!(f.directory.join("private-service-usage").join("service-usage.sqlite3").is_file(), "original cumulative ledger must survive cleanup");
    Ok(())
}

#[tokio::test]
async fn repeated_explicit_host_approval_revokes_old_consumer_acl_and_reopens_same_usage_directory() -> Result<()> {
    let f = Fixture::new().await?;
    let args = f.args("127.0.0.1:8080".parse()?, 60)?;
    let guard = SessionGuard::new(f.directory.clone(), session_snapshot(&f.directory)?, &f.sdk, 60)?;
    let mut first = start(&args, &f.sdk, f.host.clone(), &guard).await?.ok_or("first host did not start")?;
    let initial = f.exposure().await?; f.grant(&initial).await?; f.ready().await?;
    first.stop(); first.wait_stopped().await?;
    let ledger = f.directory.join("private-service-usage").join("service-usage.sqlite3");
    assert!(ledger.is_file());
    let mut second = start(&args, &f.sdk, f.host.clone(), &guard).await?.ok_or("second host did not start")?;
    let current = f.sdk.private_service_policy(&f.service.id).await?;
    assert_eq!(current.exposure.revision, initial.revision + 1);
    assert_eq!(current.exposure.service_revision, initial.service_revision + 1);
    // The policy readback contains only this new exposure revision. Old rules
    // remain revoked in storage and cannot appear as new consumer authority.
    assert!(current.rules.is_empty(), "an old consumer ACL must not survive explicit target/exposure renewal");
    assert!(f.sdk.private_services(&f.consumer.device_id, None, 10).await?.entries.is_empty());
    second.stop(); second.wait_stopped().await?;
    assert!(ledger.is_file(), "repeated host approval must retain the installation's same cumulative ledger");
    Ok(())
}

#[tokio::test]
async fn host_command_approval_deadline_withdraws_presence_and_keeps_ledger() -> Result<()> {
    let f = Fixture::new().await?;
    let args = f.args("127.0.0.1:8080".parse()?, 5)?;
    let mut command = Task::new(tokio::spawn(run(args, f.sdk.clone(), f.host.clone(), f.directory.clone(), session_snapshot(&f.directory)?)));
    let exposure = f.exposure().await?; f.grant(&exposure).await?; f.ready().await?;
    tokio::time::timeout(Duration::from_secs(12), command.join()).await???;
    let page = f.sdk.private_services(&f.consumer.device_id, None, 10).await?;
    assert!(page.entries.iter().all(|entry| entry.availability != PrivateServiceAvailability::Ready));
    assert!(f.directory.join("private-service-usage").join("service-usage.sqlite3").is_file());
    Ok(())
}
