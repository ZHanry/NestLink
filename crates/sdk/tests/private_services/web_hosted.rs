//! Same-run hosted cooperation role. The external driver owns real Caddy,
//! OS/NSS test trust and Chrome; this role owns the original SDK/private bytes.
use super::*;
use nestlink_sdk::services::{PrivateServiceHost, web_gateway::PrivateWebGatewayStopReport};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::{sync::watch, task::JoinSet};

struct Service {
    sdk: Arc<Sdk>,
    id: String,
    rule: String,
    revision: u64,
    host: PrivateServiceHost,
    gateway: PrivateWebGateway,
    usage: PathBuf,
    _server: Abort<std::io::Result<()>>,
}
impl Service {
    async fn start(target: SocketAddr) -> Result<Self> {
        let f = Fixture::configured("http", target, "direct_only", 300_000).await?;
        f.sdk.revoke_private_service(&f.view.id, &f.rule, f.exposure.revision).await?;
        let policy = f.sdk.grant_private_service(&f.view.id, PrivateServiceAclUpdate {
            expected_exposure_revision: f.exposure.revision,
            subject: PrivateServiceSubject::Installation { installation_id: f.consumer.device_id.clone() },
            expires_at_unix_ms: wall_ms()? + 300_000,
        }).await?;
        let rule = policy.rules.into_iter().find(|rule| !rule.revoked).ok_or("hosted ACL missing")?.rule_id;
        let host = f.sdk.start_private_service_host(f.host.clone(), f.consent, PrivateServiceHostConfig {
            listen: "127.0.0.1:0".parse()?, advertised_ip: "127.0.0.1".parse()?, usage_directory: f.usage.join("ledger"),
        }).await?;
        let entry = f.sdk.private_services(&f.consumer.device_id, None, 10).await?.entries.into_iter().next().ok_or("hosted entry missing")?;
        let choice = LocalProxyServiceChoice::from_local_choice(&entry, "private-web.nestlink.internal", 443, 16_384, Duration::from_secs(240))?;
        let gateway = f.sdk.start_private_web_gateway(Arc::new(f.consumer), choice, PrivateWebGatewayConfig {
            listen: "127.0.0.1:0".parse()?, origin: format!("https://{}.private.example.net", f.view.id),
        }).await?;
        Ok(Self { sdk: f.sdk, id: f.view.id, rule, revision: f.exposure.revision, host, gateway, usage: f.usage, _server: f._server })
    }
    async fn quota(&self) -> Result<serde_json::Value> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let usage = self.sdk.service_quota_usage(ServiceQuotaUsageQuery { scope: ServiceQuotaScope::Resource, scope_key: self.id.clone() }).await?;
            if usage.outstanding_bytes == 0 {
                assert!(usage.spent_bytes > 0);
                return Ok(serde_json::json!({"spent_bytes":usage.spent_bytes,"outstanding_bytes":usage.outstanding_bytes,"limit_bytes":usage.limit_bytes}));
            }
            if tokio::time::Instant::now() >= deadline { return Err("hosted quota physical settlement timed out".into()); }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Action { Launch, Observe, RevokeSecond, StopFirst, StartReplacement, Finish }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Command { sequence: u32, action: Action }

fn write(path: &std::path::Path, value: &impl Serialize) -> Result {
    nestlink_platform_security::create_private(path, &serde_json::to_vec_pretty(value)?)?;
    Ok(())
}
async fn stop(gateway: &mut PrivateWebGateway) -> Result<PrivateWebGatewayStopReport> {
    loop {
        match gateway.wait_stopped(Duration::from_secs(5)).await {
            PrivateWebGatewayWait::CleanupPending => continue,
            PrivateWebGatewayWait::Stopped(report) => { assert!(report.listener_closed); assert_eq!(report.cleanup_failures, 0); return Ok(report); }
            other => return Err(format!("hosted physical gateway receipt failed: {other:?}").into()),
        }
    }
}
struct Replacement {
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
    rejected: Arc<AtomicU64>,
    accepted: Arc<AtomicU64>,
    application_bytes: Arc<AtomicU64>,
}
impl Replacement {
    async fn start(address: SocketAddr, name: String) -> Result<Self> {
        let listener = TcpListener::bind(address).await?;
        let certificate = rcgen::generate_simple_self_signed(vec![name])?;
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?.with_no_client_auth()
            .with_single_cert(vec![certificate.cert.der().clone()], PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der()).into())?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let (stop, mut stopped) = watch::channel(false);
        let rejected = Arc::new(AtomicU64::new(0)); let accepted = Arc::new(AtomicU64::new(0)); let application_bytes = Arc::new(AtomicU64::new(0));
        let (rejects, accepts, bytes) = (rejected.clone(), accepted.clone(), application_bytes.clone());
        let task = tokio::spawn(async move {
            let mut workers = JoinSet::new();
            loop {
                tokio::select! {biased;
                    _=stopped.changed()=>break,
                    _=workers.join_next(),if !workers.is_empty()=>{},
                    connection=listener.accept(),if workers.len()<16=>{
                        let (socket, _)=connection?;
                        let (acceptor,rejects,accepts,bytes)=(acceptor.clone(),rejects.clone(),accepts.clone(),bytes.clone());
                        let mut stopped=stopped.clone();
                        workers.spawn(async move {
                            let handshake=tokio::select! {biased;_=stopped.changed()=>return, result=tokio::time::timeout(Duration::from_secs(3),acceptor.accept(socket))=>result};
                            match handshake {
                                Ok(Ok(mut tls))=>{
                                    accepts.fetch_add(1,Ordering::SeqCst);
                                    let mut buffer=[0u8;4096];
                                    if let Ok(Ok(size))=tokio::time::timeout(Duration::from_secs(1),tls.read(&mut buffer)).await {bytes.fetch_add(size as u64,Ordering::SeqCst);}
                                },
                                _=>{rejects.fetch_add(1,Ordering::SeqCst);},
                            }
                        });
                    }
                }
            }
            drop(listener);
            while workers.join_next().await.is_some() {}
            Ok(())
        });
        Ok(Self { stop, task, rejected, accepted, application_bytes })
    }
    async fn finish(self) -> Result<serde_json::Value> {
        self.stop.send_replace(true); self.task.await??;
        Ok(serde_json::json!({"rejected_tls_handshakes":self.rejected.load(Ordering::SeqCst),"accepted_tls_handshakes":self.accepted.load(Ordering::SeqCst),"application_bytes":self.application_bytes.load(Ordering::SeqCst),"listener_joined":true}))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "cooperation role; only the dedicated GitHub-hosted Caddy/Chrome workflow invokes it"]
async fn caddy_browser_fixture_role() -> Result {
    if std::env::var("NESTLINK_PRIVATE_WEB_L2").as_deref() != Ok("1")
        || std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || std::env::var("RUNNER_ENVIRONMENT").as_deref() != Ok("github-hosted")
    { return Err("R02: use the dedicated hosted private Web workflow".into()); }
    let directory = PathBuf::from(std::env::var_os("NESTLINK_PRIVATE_WEB_DIRECTORY").ok_or("private fixture directory missing")?);
    nestlink_platform_security::check_private_directory(&directory)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?; let target = listener.local_addr()?;
    let login_count = Arc::new(AtomicU64::new(0));
    let login_observer = login_count.clone();
    let backend = Router::new().route("/", get(|| async { axum::response::Html("<!doctype html><title>Private application</title><p id='application'>Private application</p>") }))
        .route("/login", post(move || {let count=login_observer.clone();async move {count.fetch_add(1,Ordering::SeqCst);backend_login().await}})).route("/me", get(backend_me)).route("/upload", post(backend_upload)).route("/socket", get(backend_socket))
        .route("/download", get(|| async { vec![37u8;2048] }))
        .route("/same", get(|| async { ([("Location","/me")],StatusCode::FOUND) }))
        .route("/outside", get(|| async { ([("Location","https://untrusted.invalid/")],StatusCode::FOUND) }));
    let _backend = Abort(tokio::spawn(async move { axum::serve(listener,backend).await }));
    let mut first = Service::start(target).await?; let mut second = Service::start(target).await?;
    let old_address = first.gateway.address();
    let old_name = first.gateway.caddy_route().pointer("/handle/0/transport/tls/server_name").and_then(serde_json::Value::as_str).ok_or("upstream name missing")?.to_owned();
    write(&directory.join("ready.json"), &serde_json::json!({"schema_version":1,"scope":"L2 hosted SDK/private Caddy Chrome; simulated DNS/test root; not public L3", "services":[{"origin":first.gateway.origin(),"owner_id":first.gateway.owner_id(),"route":first.gateway.caddy_route()},{"origin":second.gateway.origin(),"owner_id":second.gateway.owner_id(),"route":second.gateway.caddy_route()}]}))?;
    let mut replacement = None;
    let mut first_report = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(210);
    let operation = async {
        for sequence in 1..=16 {
            let path = directory.join(format!("command-{sequence}.json"));
            loop {
                if tokio::time::Instant::now() >= deadline { return Err::<(),Box<dyn std::error::Error+Send+Sync>>("hosted browser role deadline elapsed".into()); }
                match path.try_exists() {Ok(true)=>break,Ok(false)=>{},Err(error)=>return Err(error.into())}
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let bytes = nestlink_platform_security::read_private(&path, 2048)?;
            let command: Command = serde_json::from_slice(&bytes)?;
            if command.sequence != sequence { return Err("hosted command sequence differs".into()); }
            let result = match command.action {
                Action::Observe=>serde_json::json!({"backend_login_count":login_count.load(Ordering::SeqCst)}),
                Action::Launch=>{
                    let root=nestlink_platform_security::read_private(&directory.join("front-root.der"),16_384)?;
                    assert!(first.gateway.public_route_probe_with_root(&root)?.check().await?);
                    assert!(second.gateway.public_route_probe_with_root(&root)?.check().await?);
                    serde_json::json!({"launch_urls":[first.gateway.renew_launch_url()?,second.gateway.renew_launch_url()?],"original_sdk_https_readiness":true})
                },
                Action::RevokeSecond=>{second.sdk.revoke_private_service(&second.id,&second.rule,second.revision).await?;serde_json::json!({"revoked":true})},
                Action::StopFirst=>{first_report=Some(stop(&mut first.gateway).await?);serde_json::json!({"listener_closed":true,"cleanup_failures":0})},
                Action::StartReplacement=>{if first_report.is_none() || replacement.is_some(){return Err("original owner must physically stop before replacement".into());}replacement=Some(Replacement::start(old_address,old_name.clone()).await?);serde_json::json!({"same_endpoint_bound":true,"same_public_tls_name":true,"unrelated_key_and_root":true})},
                Action::Finish=>{write(&directory.join(format!("ack-{sequence}.json")),&serde_json::json!({"sequence":sequence,"finished":true}))?;return Ok(());},
            };
            write(&directory.join(format!("ack-{sequence}.json")),&serde_json::json!({"sequence":sequence,"result":result}))?;
        }
        Err("hosted command budget exhausted".into())
    }.await;
    let replacement = match replacement {Some(replacement)=>Some(replacement.finish().await),None=>None};
    let (first_report, second_report) = tokio::join!(async {match first_report {Some(report)=>Ok(report),None=>stop(&mut first.gateway).await}},stop(&mut second.gateway));
    let (first_host, second_host) = tokio::join!(first.host.wait_stopped(),second.host.wait_stopped());
    let first_report = first_report?;let second_report = second_report?;first_host?;second_host?;
    let replacement = replacement.transpose()?;
    let quotas = [first.quota().await?, second.quota().await?];
    write(&directory.join("physical-receipt.json"),&serde_json::json!({"first":{"listener_closed":first_report.listener_closed,"cleanup_failures":first_report.cleanup_failures},"second":{"listener_closed":second_report.listener_closed,"cleanup_failures":second_report.cleanup_failures},"replacement":replacement,"original_quota_usage":quotas,"host_carriers_joined":true,"public_service_grants_created":false}))?;
    operation?;
    let replacement = replacement.ok_or("replacement endpoint was not exercised")?;
    assert!(replacement["rejected_tls_handshakes"].as_u64().is_some_and(|count|count>0));
    assert_eq!(replacement["accepted_tls_handshakes"],0);assert_eq!(replacement["application_bytes"],0);
    drop(first.host);drop(second.host);
    std::fs::remove_dir_all(first.usage)?;std::fs::remove_dir_all(second.usage)?;
    Ok(())
}
