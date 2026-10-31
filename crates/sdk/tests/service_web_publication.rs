//! Opt-in public DNS/ACME acceptance. Uses the production validation path and
//! actual management HTTP -> node polling -> pinned QUIC -> Caddy -> fixed target.
//! Missing environment is a failure when this ignored test is explicitly run.
#[path = "../../node/tests/support/service_usage_directory.rs"]
mod service_usage_directory;
use service_usage_directory::ServiceUsageDirectory;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{Secret, VaultKey, hash_password, random_id};
use nestlink_identity::{PermitSigner, nodes::NodeIdentity};
use nestlink_node::control::{NodeConfig, NodeControl};
use nestlink_protocol::{NodeRole, api::*, service_plane::publication::*};
use nestlink_sdk::{
    DeploymentTrust, DeviceIdentity, Sdk,
    services::{HttpsBackendTls, LocalServiceTargetConsent, ServiceHostWait},
};
use nestlink_server::{
    AppState, router,
    service_edge::{
        self,
        caddy::{CaddyAdmin, CaddyServiceConfig},
    },
};
use nestlink_storage::Store;
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
struct Abort<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for Abort<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}
struct CaddyProcess(std::process::Child);
impl Drop for CaddyProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn required(key: &str) -> Result<String> {
    Ok(std::env::var(key)
        .map_err(|_| format!("required public acceptance fixture is missing: {key}"))?)
}
fn wall() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn uuid_env(key: &str) -> Result<String> {
    let id = required(key)?;
    if !nestlink_protocol::valid_id(&id) {
        return Err(format!("{key} must be a canonical UUID").into());
    }
    Ok(id)
}

#[tokio::test]
#[ignore = "requires dedicated public 80/443, exact A/AAAA/TXT fixtures, a Caddy binary and a reachable ACME CA; see service-web acceptance guide"]
async fn actual_public_caddy_http_https_retain_fixed_target_and_remove_routes() -> Result {
    tokio::time::timeout(Duration::from_secs(240), run()).await??;
    Ok(())
}
async fn run() -> Result {
    let deployment = uuid_env("NESTLINK_WEB_DEPLOYMENT_ID")?;
    let node_id = uuid_env("NESTLINK_WEB_NODE_ID")?;
    let service_ids = [
        uuid_env("NESTLINK_WEB_HTTP_SERVICE_ID")?,
        uuid_env("NESTLINK_WEB_HTTPS_SERVICE_ID")?,
    ];
    let suffix = required("NESTLINK_WEB_SERVICE_SUFFIX")?;
    let management_host = required("NESTLINK_WEB_MANAGEMENT_HOST")?;
    let hostnames = [
        required("NESTLINK_WEB_HTTP_HOST")?,
        required("NESTLINK_WEB_HTTPS_HOST")?,
    ];
    let public_ips: Vec<IpAddr> = required("NESTLINK_WEB_PUBLIC_IPS")?
        .split(',')
        .map(str::parse)
        .collect::<std::result::Result<_, _>>()?;
    let source_ip: IpAddr = required("NESTLINK_WEB_VISITOR_SOURCE_IP")?.parse()?;
    let work = PathBuf::from(required("NESTLINK_WEB_ARTIFACT_DIRECTORY")?)
        .join(format!("web-acceptance-{}", random_id()));
    create_fixture_root(&work)?;
    let signer = PermitSigner::generate();
    let issuer = signer.public_key();
    let policy_issuer = signer.node_policy_signer()?.public_key();
    let password = "dedicated-public-web-acceptance-password";
    let vault = VaultKey::from_bytes([43; 32]);
    let mut store = Store::in_memory(&deployment)?;
    store.bootstrap_admin("admin", password)?;
    let dummy = hash_password("unused-web-acceptance-dummy")?;
    let admin = store
        .login("admin", password, None, wall()?, &vault, &dummy)?
        .principal;
    let edge_seed = [93; 32];
    let identity = Arc::new(NodeIdentity::from_seed(&edge_seed));
    store.register_node(
        &admin,
        NodeRegistration {
            id: node_id.clone(),
            name: "dedicated-public-web-edge".into(),
            public_key: URL_SAFE_NO_PAD.encode(identity.public_key()),
            roles: vec![NodeRole::NodeEdge as i32],
            max_connections: 16,
            bytes_per_second: 1048576,
        },
    )?;
    let endpoint = nestlink_transport_quic::service::listener("127.0.0.1:0".parse()?, &identity)?;
    let namespace = store.set_service_edge_namespace(
        &admin,
        &node_id,
        ServiceEdgeNamespaceUpdate {
            expected_revision: 0,
            config: ServiceEdgeNamespace {
                service_suffix: suffix,
                management_hostname: management_host,
                public_ports: vec![29100],
                quic_address: endpoint.local_addr()?.to_string(),
            },
        },
        wall()?,
    )?;
    let http = TcpListener::bind("127.0.0.1:0").await?;
    let management = http.local_addr()?;
    let origin = format!("http://{management}");
    let app = router(AppState::new(store, vault, signer, origin.clone(), false)?);
    let _http = Abort(tokio::spawn(async move {
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
    sdk.login("admin".into(), Secret::from_text(password.into()), None)
        .await?;
    sdk.set_policy(PolicyUpdate {
        expected_revision: 1,
        policy: NetworkPolicy {
            server_forwarding: "allow".into(),
            peer_path_mode: "direct_only".into(),
            public_ingress: "enabled".into(),
        },
    })
    .await?;
    let host = Arc::new(DeviceIdentity::generate());
    sdk.enroll(
        &host,
        "fixed web target host".into(),
        "windows".into(),
        vec!["host".into(), "vp8".into()],
        "direct_only".into(),
    )
    .await?;
    let admin_reservation = TcpListener::bind("127.0.0.1:0").await?;
    let admin_address = admin_reservation.local_addr()?;
    drop(admin_reservation);
    let config = CaddyServiceConfig {
        deployment_id: deployment.clone(),
        admin: CaddyAdmin::LoopbackHttp {
            address: admin_address,
        },
        public_ips: public_ips.clone(),
        dns_json_endpoint: std::env::var("NESTLINK_WEB_DOH_URL")
            .unwrap_or_else(|_| "https://dns.google/resolve".into()),
        edge_group:None,
    };
    config.validate()?;
    let caddy_json = work.join("Caddy.json");
    std::fs::write(
        &caddy_json,
        serde_json::to_vec_pretty(&config.bootstrap(&namespace, management, &work)?)?,
    )?;
    let binary = PathBuf::from(required("NESTLINK_CADDY_BINARY")?);
    let mut command = std::process::Command::new(&binary);
    command
        .args(["run", "--config"])
        .arg(&caddy_json)
        .env("APPDATA", &work)
        .env("XDG_DATA_HOME", work.join("data"))
        .env("XDG_CONFIG_HOME", work.join("config"));
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let log = std::fs::File::create(work.join("caddy.log"))?;
    command.stdout(log.try_clone()?).stderr(log);
    let _caddy = CaddyProcess(command.spawn()?);
    let admin_url = format!("http://{admin_address}");
    let admin_client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(2))
        .build()?;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if admin_client
                .get(format!("{admin_url}/id/nestlink-services-http-{node_id}"))
                .header("Origin", &admin_url)
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await?;
    let mut service_usage_directory = ServiceUsageDirectory::new()?;
    let control = Arc::new(NodeControl::start(
        NodeConfig {
            deployment_id: deployment,
            node_id: node_id.clone(),
            control_origin: origin,
            trusted_policy_issuer: URL_SAFE_NO_PAD.encode(policy_issuer),
            identity_key_file: "unused-public-web-fixture".into(),
            service_usage_directory: Some(service_usage_directory.path().to_path_buf()),
            roles: vec![NodeRole::NodeEdge as i32],
            allow_loopback_http: true,
        },
        NodeIdentity::from_seed(&edge_seed),
    )?);
    service_usage_directory.track(&control)?;
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let edge_control = control.clone();
    let edge_node = node_id.clone();
    let mut edge = Abort(tokio::spawn(async move {
        service_edge::serve_with_caddy(
            endpoint,
            edge_control,
            identity,
            namespace,
            "127.0.0.1".parse().map_err(std::io::Error::other)?,
            Some(config),
            async {
                let _ = stopped.await;
            },
        )
        .await
    }));
    tokio::time::timeout(Duration::from_secs(5), async {
        while control.authorize(NodeRole::NodeEdge, true).is_err() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    for (index, scheme) in ["http", "https"].into_iter().enumerate() {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let fixed = listener.local_addr()?;
        let observed = Arc::new(AtomicUsize::new(0));
        let observed_copy = observed.clone();
        let expected_host = hostnames[index].clone();
        let (tls, acceptor) = backend_tls()?;
        let (backend_stop, mut backend_stopped) = tokio::sync::oneshot::channel();
        let mut backend = Abort(tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _=&mut backend_stopped=>break,
                    Some(_)=tasks.join_next()=>{},
                    accepted=listener.accept()=>{
                        let (socket,_)=accepted?;let acceptor=acceptor.clone();let expected_host=expected_host.clone();let observed=observed_copy.clone();
                        tasks.spawn(async move{if index==1 {backend_exchange(acceptor.accept(socket).await?,&expected_host,&observed).await}else{backend_exchange(socket,&expected_host,&observed).await}});
                    },
                }
            }
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        }));
        let definition = sdk
            .create_service(&ServiceCreate {
                id: service_ids[index].clone(),
                definition: ServiceDefinition {
                    name: format!("actual {scheme} fixed target"),
                    host_device_id: host.device_id.clone(),
                    edge_node_id: node_id.clone(),
                    requested_ingress: if index == 0 {
                        ServiceIngress::Http {
                            hostname: hostnames[index].clone(),
                        }
                    } else {
                        ServiceIngress::Https {
                            hostname: hostnames[index].clone(),
                        }
                    },
                    allowed_sources: vec![ServiceSourceNetwork {
                        address: source_ip.to_string(),
                        prefix: if source_ip.is_ipv4() { 32 } else { 128 },
                    }],
                    limits: ServiceLimits {
                        maximum_connections: 8,
                        bytes_per_second: 1048576,
                        maximum_bytes: 10485760,
                        idle_timeout_seconds: 10,
                    },
                },
            })
            .await?;
        let mut consent = LocalServiceTargetConsent::from_local_choice(&definition, scheme, fixed)?;
        if index == 1 {
            consent = consent.with_https_backend_tls(tls)?;
        }
        let approved = sdk.approve_service_target(&host, &consent, 180000).await?;
        let mut runtime = sdk.start_service_host(host.clone(), consent).await?;
        let id = runtime.publication_id()?;
        let sequence = control
            .service_publication(&id)?
            .lease()?
            .claims()
            .lease_sequence;
        let public = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .resolve(
                &hostnames[index],
                SocketAddr::new(public_ips[0], if index == 0 { 80 } else { 443 }),
            )
            .build()?;
        let response = public
            .post(format!("{scheme}://{}/upload?retain=1", hostnames[index]))
            .header("X-NestLink-Token", "forged")
            .header("Forwarded", "for=10.0.0.1")
            .body("actual fixed target body")
            .send()
            .await?;
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(response.text().await?, "fixed-backend-ok");
        assert_eq!(observed.load(Ordering::SeqCst), 1);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(
            control
                .service_publication(&id)?
                .lease()?
                .claims()
                .lease_sequence
                > sequence
        );
        sdk.stop_service_publication(&definition.id, approved.revision)
            .await?;
        assert!(matches!(
            runtime.wait_stopped(Duration::from_secs(5)).await,
            ServiceHostWait::Stopped(_)
        ));
        let root = format!("{admin_url}/id/nestlink-services-{scheme}-{edge_node}/handle/0/routes");
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let routes: serde_json::Value = admin_client
                    .get(&root)
                    .header("Origin", &admin_url)
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
                    .await?;
                if routes.as_array().is_some_and(Vec::is_empty) {
                    break Ok::<(), reqwest::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await??;
        let rejected = public
            .get(format!("{scheme}://{}/after-stop", hostnames[index]))
            .send()
            .await?;
        assert_ne!(rejected.status(), reqwest::StatusCode::OK);
        assert_eq!(observed.load(Ordering::SeqCst), 1);
        let _ = backend_stop.send(());
        (&mut backend.0).await??;
    }
    let _ = stop.send(());
    (&mut edge.0).await??;
    control.stop();
    std::fs::write(
        work.join("acceptance-passed.json"),
        serde_json::to_vec_pretty(
            &serde_json::json!({"http":true,"https":true,"public_dns_acme":true,"management_poll_quic_fixed_backend":true,"route_removal_confirmed":true}),
        )?,
    )?;
    Ok(())
}
fn create_fixture_root(path: &std::path::Path) -> Result {
    std::fs::create_dir_all(path)?;
    std::fs::write(path.join("index.html"), "dedicated acceptance instance")?;
    Ok(())
}
fn backend_tls() -> Result<(HttpsBackendTls, tokio_rustls::TlsAcceptor)> {
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        KeyUsagePurpose,
    };
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = ca_params.self_signed(&ca_key)?;
    let issuer = Issuer::new(ca_params, ca_key);
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(vec!["backend.nestlink.test".into()])?;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let cert = params.signed_by(&key, &issuer)?;
    let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    )?;
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    server.max_early_data_size = 0;
    Ok((
        HttpsBackendTls::new("backend.nestlink.test".into(), vec![ca.der().to_vec()])?,
        tokio_rustls::TlsAcceptor::from(Arc::new(server)),
    ))
}
async fn backend_exchange<S: AsyncRead + AsyncWrite + Unpin>(
    mut socket: S,
    hostname: &str,
    observed: &AtomicUsize,
) -> Result {
    let mut bytes = Vec::new();
    let mut byte = [0];
    while !bytes.ends_with(b"\r\n\r\n") {
        socket.read_exact(&mut byte).await?;
        bytes.push(byte[0]);
        if bytes.len() > 32768 {
            return Err("backend request too large".into());
        }
    }
    let head = std::str::from_utf8(&bytes)?.to_ascii_lowercase();
    assert!(head.starts_with("post /upload?retain=1 http/1.1\r\n"));
    assert!(head.contains(&format!("host: {hostname}\r\n")));
    assert!(!head.contains("x-nestlink-") && !head.contains("for=10.0.0.1"));
    let mut body = vec![0; b"actual fixed target body".len()];
    socket.read_exact(&mut body).await?;
    assert_eq!(body, b"actual fixed target body");
    observed.fetch_add(1, Ordering::SeqCst);
    socket
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\nfixed-backend-ok",
        )
        .await?;
    socket.shutdown().await?;
    Ok(())
}
