//! Real management authorization, installation-pinned Quinn, fixed local
//! HTTP/TCP/DNS targets, shared durable usage and physical listener release.
#[path = "private_services/relay.rs"]
mod relay;
use hickory_server::proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{Name, RData, Record, RecordType, rdata::A},
};
use nestlink_auth::{Secret, VaultKey, random_id};
use nestlink_identity::PermitSigner;
use nestlink_protocol::{
    api::*,
    service_plane::{
        SERVICE_USAGE_BYTES, ServiceQuotaScope, ServiceQuotaUsageQuery,
        ServiceUsageBudgetGrantClaims, decode_service_message,
    },
    services::private::*,
    spaces::*,
};
use nestlink_sdk::{
    DeploymentTrust, DeviceIdentity, Sdk,
    services::{
        LocalProxyServiceChoice, LocalProxyWait, LocalServiceTargetConsent, NativeStreamWait,
        PrivateServiceHostConfig,
    },
};
use nestlink_server::{AppState, router};
use nestlink_storage::Store;
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const PASSWORD: &str = "private-service-real-bytes-password";
struct Abort<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for Abort<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}
fn wall_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
struct Fixture {
    sdk: Arc<Sdk>,
    host: Arc<DeviceIdentity>,
    consumer: DeviceIdentity,
    outsider: DeviceIdentity,
    view: ServiceView,
    exposure: ServiceExposureView,
    rule: String,
    consent: LocalServiceTargetConsent,
    usage: PathBuf,
    origin: String,
    deployment: String,
    issuer: [u8; 32],
    _server: Abort<std::io::Result<()>>,
}
impl Fixture {
    async fn new(protocol: &str, target: SocketAddr) -> Result<Self> {
        Self::with_path_policy(protocol, target, "direct_only").await
    }
    async fn with_path_policy(protocol: &str, target: SocketAddr, path_mode: &str) -> Result<Self> {
        Self::configured(protocol, target, path_mode, 60000).await
    }
    async fn configured(
        protocol: &str,
        target: SocketAddr,
        path_mode: &str,
        approval_lifetime: u64,
    ) -> Result<Self> {
        let deployment = random_id();
        let signer = PermitSigner::generate();
        let issuer = signer.public_key();
        let mut store = Store::in_memory(&deployment)?;
        store.bootstrap_admin("admin", PASSWORD)?;
        // Default public ingress remains disabled and no edge is registered.
        let http = TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("http://{}", http.local_addr()?);
        let app = router(AppState::new(
            store,
            VaultKey::from_bytes([113; 32]),
            signer,
            origin.clone(),
            false,
        )?);
        let server = Abort(tokio::spawn(async move {
            axum::serve(
                http,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
        }));
        let mut sdk = Sdk::connect(
            &origin,
            DeploymentTrust {
                deployment_id: deployment.clone(),
                permit_issuer: issuer,
            },
            true,
        )
        .await?;
        sdk.login("admin".into(), Secret::from_text(PASSWORD.into()), None)
            .await?;
        if path_mode != "direct_only" {
            sdk.set_policy(PolicyUpdate {
                expected_revision: 1,
                policy: NetworkPolicy {
                    server_forwarding: "allow".into(),
                    peer_path_mode: path_mode.into(),
                    public_ingress: "disabled".into(),
                },
            })
            .await?;
        }
        let host = Arc::new(DeviceIdentity::generate());
        let consumer = DeviceIdentity::generate();
        let outsider = DeviceIdentity::generate();
        for (device, name) in [
            (&*host, "private-host"),
            (&consumer, "private-consumer"),
            (&outsider, "membership-only"),
        ] {
            sdk.enroll(
                device,
                name.into(),
                "linux-x11".into(),
                vec!["host".into(), "vp8".into()],
                path_mode.into(),
            )
            .await
            .map_err(|error| format!("enroll {name}: {error:?}"))?;
        }
        let mut space = sdk
            .create_space(SpaceCreateRequest {
                name: "Exact private consumer ACL".into(),
            })
            .await?;
        for device in [&host.device_id, &consumer.device_id, &outsider.device_id] {
            space = sdk
                .join_space_device(
                    &space.space_id,
                    SpaceDeviceJoin {
                        expected_revision: space.revision,
                        expected_membership_epoch: 0,
                        installation_id: device.clone(),
                    },
                )
                .await?;
        }
        let requested_ingress = match protocol {
            "http" => ServiceIngress::Http {
                hostname: "private.svc.example.test".into(),
            },
            "udp" => ServiceIngress::Udp { port: 29100 },
            _ => ServiceIngress::Tcp { port: 29100 },
        };
        let pending = sdk
            .create_service(&ServiceCreate {
                id: random_id(),
                definition: ServiceDefinition {
                    name: "Original local-only private target".into(),
                    host_device_id: host.device_id.clone(),
                    edge_node_id: String::new(),
                    requested_ingress,
                    allowed_sources: vec![],
                    limits: ServiceLimits {
                        maximum_connections: 4,
                        bytes_per_second: 65536,
                        maximum_bytes: 131072,
                        idle_timeout_seconds: 5,
                    },
                },
            })
            .await?;
        let consent = LocalServiceTargetConsent::from_local_choice(&pending, protocol, target)?;
        let view = sdk
            .approve_service_target(&host, &consent, approval_lifetime)
            .await?;
        let exposure = sdk
            .set_service_exposure(
                &view.id,
                ServiceExposureUpdate {
                    expected_revision: 0,
                    expected_service_revision: view.revision,
                    space_id: space.space_id,
                    mode: ServiceAccessMode::Private,
                    private_maximum_bytes: 131072,
                    public_maximum_bytes: 0,
                },
            )
            .await?;
        assert!(
            sdk.private_services(&consumer.device_id, None, 20)
                .await?
                .entries
                .is_empty()
        );
        let policy = sdk
            .grant_private_service(
                &view.id,
                PrivateServiceAclUpdate {
                    expected_exposure_revision: exposure.revision,
                    subject: PrivateServiceSubject::Installation {
                        installation_id: consumer.device_id.clone(),
                    },
                    expires_at_unix_ms: wall_ms()? + 50000,
                },
            )
            .await?;
        let rule = policy
            .rules
            .iter()
            .find(|r| !r.revoked)
            .ok_or("missing private rule")?
            .rule_id
            .clone();
        assert!(
            sdk.private_services(&outsider.device_id, None, 20)
                .await?
                .entries
                .is_empty()
        );
        let usage = std::env::var_os("NESTLINK_NODE_TEST_USAGE_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(format!("private-service-sdk-{}", random_id()));
        nestlink_platform_security::new_private_directory(&usage)?;
        Ok(Self {
            sdk: Arc::new(sdk),
            host,
            consumer,
            outsider,
            view,
            exposure,
            rule,
            consent,
            usage,
            origin,
            deployment,
            issuer,
            _server: server,
        })
    }
    fn request(&self, consumer: &DeviceIdentity) -> PrivateServiceAccessRequest {
        PrivateServiceAccessRequest {
            request_id: random_id(),
            consumer_device_id: consumer.device_id.clone(),
            expected_service_revision: self.view.revision,
            expected_exposure_revision: self.exposure.revision,
            maximum_bytes: 4096,
            route: PrivateServiceRouteRequest::Direct,
        }
    }
}

#[tokio::test]
async fn private_direct_carrier_refuses_relay_only_business_before_reserving_bytes() -> Result {
    let f = Fixture::with_path_policy("tcp", "127.0.0.1:8080".parse()?, "relay_only").await?;
    let request = f.request(&f.consumer);
    let mut host = f
        .sdk
        .start_private_service_host(
            f.host.clone(),
            f.consent,
            PrivateServiceHostConfig {
                listen: "127.0.0.1:0".parse()?,
                advertised_ip: "127.0.0.1".parse()?,
                usage_directory: f.usage.join("ledger"),
            },
        )
        .await?;
    assert!(
        f.sdk
            .request_private_service(&f.view.id, request)
            .await
            .is_err()
    );
    let usage = f
        .sdk
        .service_quota_usage(ServiceQuotaUsageQuery {
            scope: ServiceQuotaScope::Resource,
            scope_key: f.view.id.clone(),
        })
        .await?;
    assert_eq!(usage.spent_bytes, 0);
    assert_eq!(usage.outstanding_bytes, 0);
    host.wait_stopped().await?;
    drop(host);
    std::fs::remove_dir_all(f.usage)?;
    Ok(())
}

#[tokio::test]
async fn private_host_rechecks_original_consumer_login_after_signout() -> Result {
    tokio::time::timeout(Duration::from_secs(20), async {
        let backend = UdpSocket::bind("127.0.0.1:0").await?;
        let f = Fixture::new("udp", backend.local_addr()?).await?;
        let request = f.request(&f.consumer);
        let mut consumer_sdk = Sdk::connect(
            &f.origin,
            DeploymentTrust {
                deployment_id: f.deployment.clone(),
                permit_issuer: f.issuer,
            },
            true,
        )
        .await?;
        consumer_sdk
            .login("admin".into(), Secret::from_text(PASSWORD.into()), None)
            .await?;
        let mut host = f
            .sdk
            .start_private_service_host(
                f.host.clone(),
                f.consent,
                PrivateServiceHostConfig {
                    listen: "127.0.0.1:0".parse()?,
                    advertised_ip: "127.0.0.1".parse()?,
                    usage_directory: f.usage.join("ledger"),
                },
            )
            .await?;
        let lease = consumer_sdk
            .request_private_service(&f.view.id, request)
            .await?;
        assert_eq!(
            lease.claims().consumer_login_id,
            consumer_sdk
                .principal()
                .ok_or("consumer login missing")?
                .session_id
        );
        let grant: ServiceUsageBudgetGrantClaims = decode_service_message(
            &lease.lease().claims().usage_grant.claims,
            SERVICE_USAGE_BYTES,
        )?;
        let mut connection = consumer_sdk
            .connect_private_service(&f.consumer, lease)
            .await?;
        connection.send_datagram(b"authorized before signout")?;
        let mut bytes = [0; 64];
        let (length, peer) = backend.recv_from(&mut bytes).await?;
        assert_eq!(&bytes[..length], b"authorized before signout");
        backend.send_to(b"reply", peer).await?;
        assert_eq!(connection.receive_datagram().await?, b"reply");
        consumer_sdk.logout().await?;
        // The host's management login is still valid and cannot substitute for
        // the exact consumer login captured in the original business grant.
        assert!(f.sdk.me().await.is_ok());
        assert!(
            f.sdk
                .current_private_service(&f.view.id, &grant.grant_id)
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(3), connection.receive_datagram())
                .await?
                .is_err()
        );
        connection.close().await?;
        let endpoint = host.address();
        host.wait_stopped().await?;
        drop(host);
        drop(std::net::UdpSocket::bind(endpoint)?);
        std::fs::remove_dir_all(f.usage)?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn short_local_target_approval_bounds_presence_business_and_automatic_socket_release()
-> Result {
    tokio::time::timeout(Duration::from_secs(15), async {
        let backend = UdpSocket::bind("127.0.0.1:0").await?;
        let f = Fixture::configured("udp", backend.local_addr()?, "direct_only", 4000).await?;
        let request = f.request(&f.consumer);
        let approval_end = f
            .view
            .approval_expires_at_unix_ms
            .ok_or("approval deadline missing")?;
        let mut host = f
            .sdk
            .start_private_service_host(
                f.host.clone(),
                f.consent,
                PrivateServiceHostConfig {
                    listen: "127.0.0.1:0".parse()?,
                    advertised_ip: "127.0.0.1".parse()?,
                    usage_directory: f.usage.join("ledger"),
                },
            )
            .await?;
        let lease = f.sdk.request_private_service(&f.view.id, request).await?;
        assert!(lease.lease().claims().expires_at_unix_ms <= approval_end);
        let mut connection = f.sdk.connect_private_service(&f.consumer, lease).await?;
        connection.send_datagram(b"short explicit target consent")?;
        let mut bytes = [0; 64];
        let (length, peer) = backend.recv_from(&mut bytes).await?;
        assert_eq!(&bytes[..length], b"short explicit target consent");
        backend.send_to(b"approved reply", peer).await?;
        assert_eq!(connection.receive_datagram().await?, b"approved reply");
        tokio::time::sleep(Duration::from_millis(
            approval_end.saturating_sub(wall_ms()?) + 100,
        ))
        .await;
        assert!(connection.receive_datagram().await.is_err());
        connection.close().await?;
        let endpoint = host.address();
        // No host.stop/wait_stopped call has run: the original local target
        // deadline must itself retire every connection and physical listener.
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                match std::net::UdpSocket::bind(endpoint) {
                    Ok(rebound) => {
                        drop(rebound);
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                        tokio::time::sleep(Duration::from_millis(10)).await
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok::<_, std::io::Error>(())
        })
        .await??;
        host.wait_stopped().await?;
        drop(host);
        std::fs::remove_dir_all(f.usage)?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn private_tcp_preserves_half_close_without_public_edge_and_charges_original_ledgers()
-> Result {
    tokio::time::timeout(Duration::from_secs(25), async {
        let backend = TcpListener::bind("127.0.0.1:0").await?;
        let address = backend.local_addr()?;
        let backend = tokio::spawn(async move {
            let (mut stream, _) = backend.accept().await?;
            let mut input = Vec::new();
            stream.read_to_end(&mut input).await?;
            assert_eq!(input, b"private TCP request before FIN");
            tokio::time::sleep(Duration::from_millis(40)).await;
            stream
                .write_all(b"private late TCP response after FIN")
                .await?;
            stream.shutdown().await?;
            Ok::<_, std::io::Error>(())
        });
        let f = Fixture::new("tcp", address).await?;
        let request = f.request(&f.consumer);
        let denied = f.request(&f.outsider);
        let mut host = f
            .sdk
            .start_private_service_host(
                f.host.clone(),
                f.consent,
                PrivateServiceHostConfig {
                    listen: "127.0.0.1:0".parse()?,
                    advertised_ip: "127.0.0.1".parse()?,
                    usage_directory: f.usage.join("ledger"),
                },
            )
            .await?;
        assert!(
            f.sdk
                .request_private_service(&f.view.id, denied)
                .await
                .is_err()
        );
        let page = f
            .sdk
            .private_services(&f.consumer.device_id, None, 20)
            .await?;
        assert_eq!(page.entries.len(), 1);
        assert_eq!(
            page.entries[0].availability,
            PrivateServiceAvailability::Ready
        );
        let lease = f
            .sdk
            .request_private_service(&f.view.id, request.clone())
            .await?;
        let retried = f.sdk.request_private_service(&f.view.id, request).await?;
        assert_eq!(lease.digest(), retried.digest());
        let grant: ServiceUsageBudgetGrantClaims = decode_service_message(
            &lease.lease().claims().usage_grant.claims,
            SERVICE_USAGE_BYTES,
        )?;
        assert_eq!(grant.edge_node_id, f.host.device_id);
        let mut connection = f.sdk.connect_private_service(&f.consumer, lease).await?;
        connection
            .stream()?
            .write_all(b"private TCP request before FIN")
            .await?;
        connection.stream()?.shutdown().await?;
        let mut reply = Vec::new();
        connection.stream()?.read_to_end(&mut reply).await?;
        assert_eq!(reply, b"private late TCP response after FIN");
        connection.close().await?;
        backend.await??;
        let spent = (b"private TCP request before FIN".len()
            + b"private late TCP response after FIN".len()) as u64;
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let usage = f
                    .sdk
                    .service_quota_usage(ServiceQuotaUsageQuery {
                        scope: ServiceQuotaScope::Resource,
                        scope_key: f.view.id.clone(),
                    })
                    .await?;
                if usage.outstanding_bytes == 0 {
                    assert_eq!(usage.spent_bytes, spent);
                    assert_eq!(usage.limit_bytes, 131072);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        })
        .await??;
        for (scope, key) in [
            (ServiceQuotaScope::Device, f.host.device_id.clone()),
            (ServiceQuotaScope::Node, f.host.device_id.clone()),
        ] {
            let usage = f
                .sdk
                .service_quota_usage(ServiceQuotaUsageQuery {
                    scope,
                    scope_key: key,
                })
                .await?;
            assert_eq!(usage.spent_bytes, spent);
            assert_eq!(usage.outstanding_bytes, 0);
        }
        let endpoint = host.address();
        host.wait_stopped().await?;
        drop(host);
        assert_eq!(
            f.sdk
                .private_services(&f.consumer.device_id, None, 20)
                .await?
                .entries[0]
                .availability,
            PrivateServiceAvailability::Offline
        );
        let rebound = std::net::UdpSocket::bind(endpoint)?;
        drop(rebound);
        std::fs::remove_dir_all(f.usage)?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn private_http_runs_real_http_backend_and_rejects_wrong_consumer_identity() -> Result {
    tokio::time::timeout(Duration::from_secs(25),async{
        let backend=TcpListener::bind("127.0.0.1:0").await?;let address=backend.local_addr()?;
        let app=axum::Router::new().route("/fixed",axum::routing::get(||async{"HTTP through original private target"}));
        let _backend=Abort(tokio::spawn(async move{axum::serve(backend,app).await}));
        let f=Fixture::new("http",address).await?;let request=f.request(&f.consumer);
        let mut host=f.sdk.start_private_service_host(f.host.clone(),f.consent,PrivateServiceHostConfig{
            listen:"127.0.0.1:0".parse()?,advertised_ip:"127.0.0.1".parse()?,usage_directory:f.usage.join("ledger")}).await?;
        let lease=f.sdk.request_private_service(&f.view.id,request).await?;
        assert!(f.sdk.connect_private_service(&f.outsider,lease.clone()).await.is_err());
        let mut connection=f.sdk.connect_private_service(&f.consumer,lease).await?;
        connection.stream()?.write_all(b"GET /fixed HTTP/1.1\r\nHost: private.svc.example.test\r\nConnection: close\r\n\r\n").await?;
        let mut response=Vec::new();connection.stream()?.read_to_end(&mut response).await?;
        let response=String::from_utf8(response)?;assert!(response.starts_with("HTTP/1.1 200"));
        assert!(response.ends_with("HTTP through original private target"));
        connection.close().await?;let endpoint=host.address();host.wait_stopped().await?;drop(host);
        drop(std::net::UdpSocket::bind(endpoint)?);std::fs::remove_dir_all(f.usage)?;
        Ok::<_,Box<dyn std::error::Error+Send+Sync>>(())
    }).await??;
    Ok(())
}

#[tokio::test]
async fn private_udp_preserves_empty_datagrams_transports_dns_and_revokes_live_mapping() -> Result {
    tokio::time::timeout(Duration::from_secs(25),async{
        let backend=UdpSocket::bind("127.0.0.1:0").await?;let address=backend.local_addr()?;
        let backend=tokio::spawn(async move{
            let mut buffer=[0;2048];let (length,peer)=backend.recv_from(&mut buffer).await?;
            assert_eq!(length,0);backend.send_to(&[],peer).await?;
            let (length,peer)=backend.recv_from(&mut buffer).await?;
            let request=Message::from_vec(&buffer[..length])?;
            assert_eq!(request.queries[0].name().to_string(),"approved.private.test.");
            let mut response=Message::new(request.metadata.id,MessageType::Response,OpCode::Query);
            response.add_query(request.queries[0].clone());response.metadata.response_code=ResponseCode::NoError;
            response.add_answer(Record::from_rdata(Name::from_ascii("approved.private.test.")?,30,
                RData::A(A("192.0.2.81".parse()?))));
            backend.send_to(&response.to_vec()?,peer).await?;
            Ok::<_,Box<dyn std::error::Error+Send+Sync>>(())
        });
        let f=Fixture::new("udp",address).await?;let request=f.request(&f.consumer);
        let mut host=f.sdk.start_private_service_host(f.host.clone(),f.consent,PrivateServiceHostConfig{
            listen:"127.0.0.1:0".parse()?,advertised_ip:"127.0.0.1".parse()?,usage_directory:f.usage.join("ledger")}).await?;
        let lease=f.sdk.request_private_service(&f.view.id,request).await?;
        let mut connection=f.sdk.connect_private_service(&f.consumer,lease).await?;
        connection.send_datagram(&[])?;assert!(connection.receive_datagram().await?.is_empty());
        assert!(connection.send_datagram(&[0;1170]).is_err());
        let mut query=Message::new(8173,MessageType::Query,OpCode::Query);
        query.add_query(Query::query(Name::from_ascii("approved.private.test.")?,RecordType::A));
        connection.send_datagram(&query.to_vec()?)?;
        let response=Message::from_vec(&connection.receive_datagram().await?)?;
        assert_eq!(response.metadata.id,8173);assert_eq!(response.metadata.response_code,ResponseCode::NoError);
        assert!(response.answers.iter().any(|r|matches!(&r.data,RData::A(A(ip)) if *ip=="192.0.2.81".parse::<std::net::Ipv4Addr>().unwrap())));
        backend.await??;
        f.sdk.revoke_private_service(&f.view.id,&f.rule,f.exposure.revision).await?;
        assert!(tokio::time::timeout(Duration::from_secs(3),connection.receive_datagram()).await?.is_err());
        assert!(f.sdk.private_services(&f.consumer.device_id,None,20).await?.entries.is_empty());
        connection.close().await?;let endpoint=host.address();host.wait_stopped().await?;drop(host);
        drop(std::net::UdpSocket::bind(endpoint)?);std::fs::remove_dir_all(f.usage)?;
        Ok::<_,Box<dyn std::error::Error+Send+Sync>>(())
    }).await??;
    Ok(())
}

#[tokio::test]
async fn standard_socks_client_uses_private_target_and_stops_stalled_workers_and_credentials()
-> Result {
    tokio::time::timeout(Duration::from_secs(30), async {
        let backend = TcpListener::bind("127.0.0.1:0").await?;
        let address = backend.local_addr()?;
        let backend = tokio::spawn(async move {
            let (mut stream, _) = backend.accept().await?;
            let mut request = Vec::new();
            stream.read_to_end(&mut request).await?;
            assert_eq!(request, b"standard SOCKS request before FIN");
            stream
                .write_all(b"private response after SOCKS FIN")
                .await?;
            stream.shutdown().await?;
            Ok::<_, std::io::Error>(())
        });
        let f = Fixture::new("tcp", address).await?;
        let mut host = f
            .sdk
            .start_private_service_host(
                f.host.clone(),
                f.consent,
                PrivateServiceHostConfig {
                    listen: "127.0.0.1:0".parse()?,
                    advertised_ip: "127.0.0.1".parse()?,
                    usage_directory: f.usage.join("ledger"),
                },
            )
            .await?;
        let entry = f
            .sdk
            .private_services(&f.consumer.device_id, None, 20)
            .await?
            .entries
            .remove(0);
        let consumer = Arc::new(f.consumer);
        let choose = |lifetime| {
            LocalProxyServiceChoice::from_local_choice(
                &entry,
                "fixed.nestlink.internal",
                29100,
                4096,
                lifetime,
            )
        };
        let credentials_directory = f.usage.join("socks-credentials");
        nestlink_platform_security::new_private_directory(&credentials_directory)?;
        // Listener collision fails before creating a credential owner.
        let collision = TcpListener::bind("127.0.0.1:0").await?;
        assert!(
            f.sdk
                .start_private_service_socks(
                    consumer.clone(),
                    choose(Duration::from_secs(20))?,
                    collision.local_addr()?,
                    &credentials_directory
                )
                .await
                .is_err()
        );
        assert_eq!(std::fs::read_dir(&credentials_directory)?.count(), 0);
        drop(collision);
        let mut proxy = f
            .sdk
            .start_private_service_socks(
                consumer.clone(),
                choose(Duration::from_secs(20))?,
                "127.0.0.1:0".parse()?,
                &credentials_directory,
            )
            .await?;
        #[derive(serde::Deserialize)]
        struct Credentials {
            username: String,
            password: String,
        }
        let credential_path = proxy.credentials_path().to_path_buf();
        let credentials: Credentials = serde_json::from_slice(
            &nestlink_platform_security::read_private(&credential_path, 4096)?,
        )?;
        let connect = |target: String, port: u16, password: String| {
            fast_socks5::client::Socks5Stream::connect_with_password(
                proxy.address(),
                target,
                port,
                credentials.username.clone(),
                password,
                fast_socks5::client::Config::default(),
            )
        };
        assert!(
            connect(
                "fixed.nestlink.internal".into(),
                29100,
                "wrong-password".into()
            )
            .await
            .is_err()
        );
        assert!(
            connect(
                "other.nestlink.internal".into(),
                29100,
                credentials.password.clone()
            )
            .await
            .is_err()
        );
        assert!(
            connect(
                "fixed.nestlink.internal".into(),
                29101,
                credentials.password.clone()
            )
            .await
            .is_err()
        );
        assert!(
            connect(
                "127.0.0.1".into(),
                address.port(),
                credentials.password.clone()
            )
            .await
            .is_err()
        );
        let mut stream = connect(
            "fixed.nestlink.internal".into(),
            29100,
            credentials.password.clone(),
        )
        .await?;
        stream
            .write_all(b"standard SOCKS request before FIN")
            .await?;
        stream.shutdown().await?;
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).await?;
        assert_eq!(reply, b"private response after SOCKS FIN");
        drop(stream);
        backend.await??;
        // The setup worker owns this accepted socket even without a SOCKS greeting.
        let mut stalled = TcpStream::connect(proxy.address()).await?;
        stalled.write_all(&[5, 1, 2]).await?;
        let mut authentication_choice = [0; 2];
        stalled.read_exact(&mut authentication_choice).await?;
        assert_eq!(authentication_choice, [5, 2]);
        let proxy_address = proxy.address();
        let report = match proxy.wait_stopped(Duration::from_secs(5)).await {
            LocalProxyWait::Stopped(report) => report,
            other => {
                return Err(format!("SOCKS shutdown did not confirm cleanup: {other:?}").into());
            }
        };
        assert!(report.credentials_removed);
        assert_eq!(report.cleanup_failures, 0);
        assert!(report.rejected_connections >= 4);
        assert_eq!(report.accepted_connections, report.completed_connections);
        assert!(!credential_path.exists());
        let mut last = [0; 1];
        assert_eq!(stalled.read(&mut last).await?, 0);
        drop(stalled);
        drop(proxy);
        drop(TcpListener::bind(proxy_address).await?);
        // Expiration is enforced by the owner without a caller's shutdown signal.
        let mut expiring = f
            .sdk
            .start_private_service_socks(
                consumer,
                choose(Duration::from_millis(100))?,
                "127.0.0.1:0".parse()?,
                &credentials_directory,
            )
            .await?;
        let expiring_address = expiring.address();
        let expiring_credentials = expiring.credentials_path().to_path_buf();
        tokio::time::sleep(Duration::from_millis(180)).await;
        assert!(TcpStream::connect(expiring_address).await.is_err());
        assert!(!expiring_credentials.exists());
        assert!(matches!(
            expiring.wait_stopped(Duration::from_secs(2)).await,
            LocalProxyWait::Stopped(_)
        ));
        drop(expiring);
        drop(TcpListener::bind(expiring_address).await?);
        let endpoint = host.address();
        host.wait_stopped().await?;
        drop(host);
        drop(std::net::UdpSocket::bind(endpoint)?);
        std::fs::remove_dir_all(f.usage)?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn standard_socks_udp_association_keeps_empty_boundaries_and_exact_local_peer() -> Result {
    tokio::time::timeout(Duration::from_secs(30), async {
        use fast_socks5::{
            AuthenticationMethod, Socks5Command,
            client::{Config, Socks5Stream},
            new_udp_header, parse_udp_request,
            util::target_addr::TargetAddr,
        };
        let backend = UdpSocket::bind("127.0.0.1:0").await?;
        let address = backend.local_addr()?;
        let maximum = nestlink_node::service_plane::DatagramPacket::MAX_PAYLOAD;
        let large = vec![0x6b; maximum];
        let expected = large.clone();
        let backend = tokio::spawn(async move {
            let mut bytes = vec![0; 65536];
            let (length, peer) = backend.recv_from(&mut bytes).await?;
            assert_eq!(length, 0);
            backend.send_to(&[], peer).await?;
            // Any falsely accepted negative packet below reaches this real
            // backend and fails the exact second application-message assertion.
            let (length, peer) = backend.recv_from(&mut bytes).await?;
            assert_eq!(&bytes[..length], expected);
            backend.send_to(&expected, peer).await?;
            Ok::<_, std::io::Error>(())
        });
        let f = Fixture::new("udp", address).await?;
        let mut host = f
            .sdk
            .start_private_service_host(
                f.host.clone(),
                f.consent,
                PrivateServiceHostConfig {
                    listen: "127.0.0.1:0".parse()?,
                    advertised_ip: "127.0.0.1".parse()?,
                    usage_directory: f.usage.join("ledger"),
                },
            )
            .await?;
        let entry = f
            .sdk
            .private_services(&f.consumer.device_id, None, 20)
            .await?
            .entries
            .remove(0);
        let consumer = Arc::new(f.consumer);
        let choice = LocalProxyServiceChoice::from_local_choice(
            &entry,
            "dns.nestlink.internal",
            53,
            4096,
            Duration::from_secs(20),
        )?;
        let credentials_directory = f.usage.join("socks-udp-credentials");
        nestlink_platform_security::new_private_directory(&credentials_directory)?;
        let mut proxy = f
            .sdk
            .start_private_service_socks(
                consumer,
                choice,
                "127.0.0.1:0".parse()?,
                &credentials_directory,
            )
            .await?;
        #[derive(serde::Deserialize)]
        struct Credentials {
            username: String,
            password: String,
        }
        let credential_path = proxy.credentials_path().to_path_buf();
        let credentials: Credentials = serde_json::from_slice(
            &nestlink_platform_security::read_private(&credential_path, 4096)?,
        )?;
        // Authentication happens through the mature client's standard API.
        // A wildcard source is deliberately refused; it cannot silently select
        // whichever unrelated local process sends the first datagram.
        let mut refused = Socks5Stream::use_stream(
            TcpStream::connect(proxy.address()).await?,
            Some(AuthenticationMethod::Password {
                username: credentials.username.clone(),
                password: credentials.password.clone(),
            }),
            Config::default(),
        )
        .await?;
        assert!(
            refused
                .request(
                    Socks5Command::UDPAssociate,
                    TargetAddr::Ip("0.0.0.0:0".parse()?)
                )
                .await
                .is_err()
        );
        drop(refused);
        let udp = UdpSocket::bind("127.0.0.1:0").await?;
        let mut control = Socks5Stream::use_stream(
            TcpStream::connect(proxy.address()).await?,
            Some(AuthenticationMethod::Password {
                username: credentials.username.clone(),
                password: credentials.password.clone(),
            }),
            Config::default(),
        )
        .await?;
        let relay = match control
            .request(
                Socks5Command::UDPAssociate,
                TargetAddr::Ip(udp.local_addr()?),
            )
            .await?
        {
            TargetAddr::Ip(address) => address,
            _ => return Err("SOCKS UDP relay address was not fixed".into()),
        };
        assert!(relay.ip().is_loopback());
        assert_ne!(relay.port(), 0);
        let header = new_udp_header(("dns.nestlink.internal", 53))?;
        udp.send_to(&header, relay).await?;
        let mut reply = vec![0; 65536];
        let (length, source) = udp.recv_from(&mut reply).await?;
        assert_eq!(source, relay);
        let (fragment, target, payload) = parse_udp_request(&reply[..length]).await?;
        assert_eq!(fragment, 0);
        assert!(payload.is_empty());
        assert!(matches!(target,TargetAddr::Domain(alias,53)if alias=="dns.nestlink.internal"));
        for mut packet in [
            new_udp_header(("other.nestlink.internal", 53))?,
            new_udp_header(("dns.nestlink.internal", 54))?,
            new_udp_header(address)?,
        ] {
            packet.extend_from_slice(b"denied target");
            udp.send_to(&packet, relay).await?;
        }
        let mut fragmented = header.clone();
        fragmented[2] = 1;
        fragmented.extend_from_slice(b"denied fragment");
        udp.send_to(&fragmented, relay).await?;
        let mut oversized = header.clone();
        oversized.extend_from_slice(&vec![0x7a; maximum + 1]);
        udp.send_to(&oversized, relay).await?;
        let mut reserved = header.clone();
        reserved[0] = 1;
        reserved.extend_from_slice(b"denied reserved header");
        udp.send_to(&reserved, relay).await?;
        let stranger = UdpSocket::bind("127.0.0.1:0").await?;
        let mut wrong_peer = header.clone();
        wrong_peer.extend_from_slice(b"denied process");
        stranger.send_to(&wrong_peer, relay).await?;
        assert!(
            tokio::time::timeout(Duration::from_millis(40), stranger.recv_from(&mut reply))
                .await
                .is_err()
        );
        let mut packet = header;
        packet.extend_from_slice(&large);
        udp.send_to(&packet, relay).await?;
        let (length, source) = udp.recv_from(&mut reply).await?;
        assert_eq!(source, relay);
        let (fragment, _, payload) = parse_udp_request(&reply[..length]).await?;
        assert_eq!(fragment, 0);
        assert_eq!(payload, large);
        backend.await??;
        drop(control);
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                match UdpSocket::bind(relay).await {
                    Ok(socket) => {
                        drop(socket);
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                        tokio::time::sleep(Duration::from_millis(10)).await
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok::<_, std::io::Error>(())
        })
        .await??;
        // A second live association is cancelled through the proxy owner.
        let mut second = Socks5Stream::use_stream(
            TcpStream::connect(proxy.address()).await?,
            Some(AuthenticationMethod::Password {
                username: credentials.username,
                password: credentials.password,
            }),
            Config::default(),
        )
        .await?;
        let second_relay = match second
            .request(
                Socks5Command::UDPAssociate,
                TargetAddr::Ip(udp.local_addr()?),
            )
            .await?
        {
            TargetAddr::Ip(address) => address,
            _ => return Err("second UDP relay address missing".into()),
        };
        let proxy_address = proxy.address();
        let report = match proxy.wait_stopped(Duration::from_secs(5)).await {
            LocalProxyWait::Stopped(report) => report,
            other => return Err(format!("UDP SOCKS cleanup incomplete: {other:?}").into()),
        };
        assert!(report.credentials_removed);
        assert_eq!(report.cleanup_failures, 0);
        assert_eq!(report.forwarded_datagrams, 4);
        assert!(report.discarded_datagrams >= 7);
        assert_eq!(report.accepted_connections, report.completed_connections);
        let mut end = [0; 1];
        assert_eq!(second.read(&mut end).await?, 0);
        drop(second);
        drop(proxy);
        assert!(!credential_path.exists());
        drop(UdpSocket::bind(second_relay).await?);
        drop(TcpListener::bind(proxy_address).await?);
        let endpoint = host.address();
        host.wait_stopped().await?;
        drop(host);
        drop(std::net::UdpSocket::bind(endpoint)?);
        std::fs::remove_dir_all(f.usage)?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn native_private_stream_transports_real_bytes_and_stops_active_backend_and_os_endpoint()
-> Result {
    tokio::time::timeout(Duration::from_secs(30), async {
        let backend = TcpListener::bind("127.0.0.1:0").await?;
        let address = backend.local_addr()?;
        let (active, activated) = tokio::sync::oneshot::channel();
        let backend = tokio::spawn(async move {
            let (mut first, _) = backend.accept().await?;
            let mut request = [0; 18];
            first.read_exact(&mut request).await?;
            assert_eq!(&request, b"native fixed query");
            first.write_all(b"native fixed response").await?;
            let mut end = [0; 1];
            assert_eq!(first.read(&mut end).await?, 0);
            first.shutdown().await?;
            let (mut second, _) = backend.accept().await?;
            let mut request = [0; 17];
            second.read_exact(&mut request).await?;
            assert_eq!(&request, b"native live query");
            let _ = active.send(());
            assert_eq!(second.read(&mut end).await?, 0);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let f = Fixture::new("tcp", address).await?;
        let mut host = f
            .sdk
            .start_private_service_host(
                f.host.clone(),
                f.consent,
                PrivateServiceHostConfig {
                    listen: "127.0.0.1:0".parse()?,
                    advertised_ip: "127.0.0.1".parse()?,
                    usage_directory: f.usage.join("ledger"),
                },
            )
            .await?;
        let entry = f
            .sdk
            .private_services(&f.consumer.device_id, None, 20)
            .await?
            .entries
            .remove(0);
        let choice = LocalProxyServiceChoice::from_local_choice(
            &entry,
            "fixed.nestlink.internal",
            29100,
            4096,
            Duration::from_secs(20),
        )?;
        // Keep the Unix socket below the kernel's pathname byte limit. The
        // existing owner-private directory boundary still authenticates it.
        let directory = std::env::temp_dir().join(format!("nl-{}", random_id()));
        nestlink_platform_security::new_private_directory(&directory)?;
        let mut proxy = f
            .sdk
            .start_private_service_native_stream(Arc::new(f.consumer), choice, &directory)
            .await?;
        let endpoint = proxy.endpoint().to_path_buf();
        let mut first = nestlink_platform_security::local_stream::connect(&endpoint).await?;
        first.write_all(b"native fixed query").await?;
        let mut response = [0; 21];
        first.read_exact(&mut response).await?;
        assert_eq!(&response, b"native fixed response");
        drop(first);
        let mut second = nestlink_platform_security::local_stream::connect(&endpoint).await?;
        second.write_all(b"native live query").await?;
        activated.await?;
        let report = match proxy.wait_stopped(Duration::from_secs(5)).await {
            NativeStreamWait::Stopped(report) => report,
            other => return Err(format!("native stream cleanup incomplete: {other:?}").into()),
        };
        assert!(report.endpoint_removed);
        assert_eq!(report.cleanup_failures, 0);
        assert_eq!(report.accepted_connections, 2);
        assert_eq!(report.completed_connections, 2);
        assert_eq!(report.rejected_connections, 0);
        let mut end = [0; 1];
        match second.read(&mut end).await {
            Ok(length) => assert_eq!(length, 0),
            Err(error) => assert!(matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
            )),
        }
        drop(second);
        drop(proxy);
        backend.await??;
        assert!(
            nestlink_platform_security::local_stream::connect(&endpoint)
                .await
                .is_err()
        );
        let endpoint = host.address();
        host.wait_stopped().await?;
        drop(host);
        drop(std::net::UdpSocket::bind(endpoint)?);
        std::fs::remove_dir_all(directory)?;
        std::fs::remove_dir_all(f.usage)?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn native_private_stream_refuses_udp_without_creating_an_os_endpoint_or_reservation() -> Result
{
    let f = Fixture::new("udp", "127.0.0.1:29101".parse()?).await?;
    let mut host = f
        .sdk
        .start_private_service_host(
            f.host.clone(),
            f.consent,
            PrivateServiceHostConfig {
                listen: "127.0.0.1:0".parse()?,
                advertised_ip: "127.0.0.1".parse()?,
                usage_directory: f.usage.join("ledger"),
            },
        )
        .await?;
    let entry = f
        .sdk
        .private_services(&f.consumer.device_id, None, 20)
        .await?
        .entries
        .remove(0);
    let choice = LocalProxyServiceChoice::from_local_choice(
        &entry,
        "fixed.nestlink.internal",
        29100,
        4096,
        Duration::from_secs(20),
    )?;
    let directory = std::env::temp_dir().join(format!("nl-{}", random_id()));
    nestlink_platform_security::new_private_directory(&directory)?;
    assert!(
        f.sdk
            .start_private_service_native_stream(Arc::new(f.consumer), choice, &directory)
            .await
            .is_err()
    );
    assert_eq!(std::fs::read_dir(&directory)?.count(), 0);
    let usage = f
        .sdk
        .service_quota_usage(ServiceQuotaUsageQuery {
            scope: ServiceQuotaScope::Resource,
            scope_key: f.view.id.clone(),
        })
        .await?;
    assert_eq!(usage.spent_bytes, 0);
    assert_eq!(usage.outstanding_bytes, 0);
    host.wait_stopped().await?;
    drop(host);
    std::fs::remove_dir_all(directory)?;
    std::fs::remove_dir_all(f.usage)?;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn native_private_unix_stream_preserves_request_fin_and_replacement_path() -> Result {
    tokio::time::timeout(Duration::from_secs(25), async {
        let backend = TcpListener::bind("127.0.0.1:0").await?;
        let address = backend.local_addr()?;
        let backend = tokio::spawn(async move {
            let (mut stream, _) = backend.accept().await?;
            let mut request = Vec::new();
            stream.read_to_end(&mut request).await?;
            assert_eq!(request, b"native request before FIN");
            stream.write_all(b"native late response after FIN").await?;
            stream.shutdown().await?;
            Ok::<_, std::io::Error>(())
        });
        let f = Fixture::new("tcp", address).await?;
        let mut host = f
            .sdk
            .start_private_service_host(
                f.host.clone(),
                f.consent,
                PrivateServiceHostConfig {
                    listen: "127.0.0.1:0".parse()?,
                    advertised_ip: "127.0.0.1".parse()?,
                    usage_directory: f.usage.join("ledger"),
                },
            )
            .await?;
        let entry = f
            .sdk
            .private_services(&f.consumer.device_id, None, 20)
            .await?
            .entries
            .remove(0);
        let consumer = Arc::new(f.consumer);
        let choice = || {
            LocalProxyServiceChoice::from_local_choice(
                &entry,
                "fixed.nestlink.internal",
                29100,
                4096,
                Duration::from_secs(20),
            )
        };
        let directory = std::env::temp_dir().join(format!("nl-{}", random_id()));
        nestlink_platform_security::new_private_directory(&directory)?;
        let mut proxy = f
            .sdk
            .start_private_service_native_stream(consumer.clone(), choice()?, &directory)
            .await?;
        let mut local = nestlink_platform_security::local_stream::connect(proxy.endpoint()).await?;
        local.write_all(b"native request before FIN").await?;
        local.shutdown().await?;
        let mut response = Vec::new();
        local.read_to_end(&mut response).await?;
        assert_eq!(response, b"native late response after FIN");
        drop(local);
        backend.await??;
        assert!(matches!(
            proxy.wait_stopped(Duration::from_secs(5)).await,
            NativeStreamWait::Stopped(_)
        ));
        drop(proxy);
        let mut replaced = f
            .sdk
            .start_private_service_native_stream(consumer, choice()?, &directory)
            .await?;
        let endpoint = replaced.endpoint().to_path_buf();
        std::fs::remove_file(&endpoint)?;
        std::fs::write(&endpoint, b"replacement belongs to its new owner")?;
        assert!(
            nestlink_platform_security::local_stream::connect(&endpoint)
                .await
                .is_err()
        );
        let report = match replaced.wait_stopped(Duration::from_secs(5)).await {
            NativeStreamWait::CleanupFailed(report) => report,
            other => return Err(format!("replacement cleanup claimed success: {other:?}").into()),
        };
        assert!(!report.endpoint_removed);
        assert!(report.cleanup_failures > 0);
        assert_eq!(report.accepted_connections, 0);
        drop(replaced);
        assert_eq!(
            std::fs::read(&endpoint)?,
            b"replacement belongs to its new owner"
        );
        let endpoint = host.address();
        host.wait_stopped().await?;
        drop(host);
        drop(std::net::UdpSocket::bind(endpoint)?);
        std::fs::remove_dir_all(directory)?;
        std::fs::remove_dir_all(f.usage)?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    Ok(())
}
