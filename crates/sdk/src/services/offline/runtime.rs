use super::*;
use nestlink_platform_security::local_stream::Listener;
use std::sync::atomic::Ordering;
use tokio::io::{AsyncRead, AsyncWrite};

const MAX_FLOWS: usize = 8;
#[derive(Default)]
struct FlowOutcome {
    failed: bool,
    released: bool,
    cleanup_failed: bool,
}
struct Active(Arc<Shared>);
impl Active {
    fn new(shared: Arc<Shared>) -> Self {
        shared.active.fetch_add(1, Ordering::AcqRel);
        Self(shared)
    }
}
impl Drop for Active {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
    }
}
fn peer(
    shared: &Shared,
    connection: &quinn::Connection,
    endpoint: usize,
) -> Result<[u8; 32], SdkError> {
    let key = shared.lock()?.authority.claims().members[endpoint].public_key;
    let actual = connection.peer_identity().ok_or(SdkError::Trust)?;
    if nestlink_transport_stream::tls::peer_identity_fingerprint(actual.as_ref())
        .map_err(|_| SdkError::Trust)?
        != digest(&key)
        || !carrier::negotiated_service(connection)
    {
        return Err(SdkError::Trust);
    }
    Ok(key)
}
impl crate::offline_channel::Owner for Shared {
    fn claims(&self)->Result<nestlink_protocol::offline::OfflineGrantBundleClaims,SdkError> {Ok(self.lock()?.authority.claims().clone())}
    fn digest(&self)->Result<[u8;32],SdkError> {Ok(self.lock()?.authority.digest())}
    fn sign(&self,wall:u64,binding:&nestlink_protocol::offline::channel::OfflineChannelBinding)->Result<Vec<u8>,SdkError> {Ok(self.lock()?.authority.sign_channel_proof(wall,binding)?)}
    fn authenticate(&self,wall:u64,transport:OfflineDirectTransport,peer:&[u8;32])->Result<(),SdkError> {Ok(self.lock()?.authority.authenticate_reserved_connection(wall,transport,peer)?)}
}
async fn host_proof(shared:&Shared,host:&DeviceIdentity,connection:&quinn::Connection)->Result<BiStream,SdkError> {
    let key=peer(shared,connection,0)?;
    let (mut send,mut recv)=connection.accept_bi().await.map_err(std::io::Error::other)?;
    crate::offline_channel::prove(shared,host,&mut recv,&mut send,1,OfflineDirectTransport::Quic,&key).await?;
    Ok(BiStream::new(send,recv))
}
async fn source_proof(shared:&Shared,consumer:&DeviceIdentity,connection:&quinn::Connection)->Result<BiStream,SdkError> {
    let key=peer(shared,connection,1)?;
    let (mut send,mut recv)=connection.open_bi().await.map_err(std::io::Error::other)?;
    crate::offline_channel::prove(shared,consumer,&mut recv,&mut send,0,OfflineDirectTransport::Quic,&key).await?;
    Ok(BiStream::new(send,recv))
}
async fn forward<A: AsyncRead + AsyncWrite + Unpin, B: AsyncRead + AsyncWrite + Unpin>(
    shared: Arc<Shared>,
    carrier: A,
    mut application: B,
) -> Result<(), SdkError> {
    shared.check()?;
    let _active = Active::new(shared.clone());
    let mut metered = guard::Metered {
        inner: carrier,
        shared: shared.clone(),
    };
    tokio::select! {biased;
        _=shared.stopped()=>Ok(()),
        result=tokio::io::copy_bidirectional(&mut metered,&mut application)=>result.map(|_|()).map_err(Into::into),
    }
}
fn consent_current(shared: &Shared, consent: &LocalServiceTargetConsent) -> Result<(), SdkError> {
    let state = shared.lock()?;
    let c = state.authority.claims();
    let OfflineBusiness::PrivateService {
        service_id,
        service_revision,
        definition_digest,
        target_digest,
    } = &c.business
    else {
        return Err(SdkError::Trust);
    };
    if service_id != &consent.service_id
        || *service_revision != consent.revision.checked_add(1).ok_or(SdkError::Trust)?
        || *definition_digest
            != nestlink_identity::services::decode_digest(&consent.definition_sha256)?
        || *target_digest != nestlink_identity::services::decode_digest(&consent.target_sha256)?
        || consent.host_device_id != c.members[1].installation_id
        || consent.account_id != c.members[1].account_id
        || !["tcp", "http", "https"].contains(&consent.protocol.as_str())
        || consent.protocol == "https" && consent.backend_tls.is_none()
        || !c
            .connection
            .direct_transports
            .contains(&OfflineDirectTransport::Quic)
    {
        return Err(SdkError::Trust);
    }
    Ok(())
}
async fn recovery_monitor(shared: Arc<Shared>, sdk: Arc<Sdk>) {
    let space = match shared.lock() {
        Ok(state) => state.authority.claims().space_id.clone(),
        Err(_) => {
            shared.stop();
            return;
        }
    };
    loop {
        tokio::select! {biased;_ = shared.stopped()=>break,_=tokio::time::sleep(Duration::from_secs(2))=>{}}
        let response = tokio::select! {biased;_ = shared.stopped()=>break,result=sdk.offline_policy(&space)=>result};
        // Failed probes cannot extend or replace authority. A freshly
        // authenticated response enters the paused original recovery gate
        // synchronously before the next business poll can pass it.
        if response.is_ok() && shared.synchronize(&sdk).await.is_err() {
            break;
        }
    }
}
pub(super) async fn host(
    sdk: &Arc<Sdk>,
    host: Arc<DeviceIdentity>,
    consumed: ConsumedOfflineBundle,
    consent: LocalServiceTargetConsent,
    listen: SocketAddr,
) -> Result<OfflinePrivateRuntime, SdkError> {
    if consumed.claims().deployment_id != sdk.trust.deployment_id {
        return Err(SdkError::Trust);
    }
    let shared = Shared::new(consumed, &host, 1)?;
    consent_current(&shared, &consent)?;
    let key = shared.lock()?.authority.claims().members[0].public_key;
    let listener = PrivateListener::bind_pinned(listen, &host.identity, digest(&key))
        .map_err(SdkError::NodeQuic)?;
    let address = listener.endpoint.local_addr()?;
    let monitor = tokio::spawn(recovery_monitor(shared.clone(), sdk.clone()));
    let owner = shared.clone();
    let task = tokio::spawn(async move {
        let report = run_host(owner, host, Arc::new(consent), listener).await;
        monitor.abort();
        let _ = monitor.await;
        report
    });
    Ok(OfflinePrivateRuntime {
        shared,
        address: Some(address),
        endpoint: None,
        task: Some(task),
        report: None,
        runtime: tokio::runtime::Handle::current(),
    })
}
async fn host_flow(
    shared: Arc<Shared>,
    host: Arc<DeviceIdentity>,
    consent: Arc<LocalServiceTargetConsent>,
    incoming: quinn::Incoming,
) -> Result<(), SdkError> {
    shared
        .lock()?
        .authority
        .reserve_connection_attempt(wall()?, OfflineDirectTransport::Quic)?;
    let connection = tokio::select! {biased;
        _=shared.stopped()=>return Ok(()),
        result=tokio::time::timeout(Duration::from_secs(2),incoming)=>result.map_err(|_|SdkError::Timeout)?.map_err(io::Error::other)?,
    };
    let result=async {
        let stream=tokio::select! {biased;
            _=shared.stopped()=>return Ok(()),
            result=tokio::time::timeout(Duration::from_secs(2),host_proof(&shared,&host,&connection))=>result.map_err(|_|SdkError::Timeout)??,
        };
        consent_current(&shared,&consent)?;
        let target=tokio::select! {biased;
            _=shared.stopped()=>return Ok(()),
            result=tokio::time::timeout(Duration::from_secs(2),tokio::net::TcpStream::connect(consent.address))=>result.map_err(|_|SdkError::Timeout)??,
        };
        target.set_nodelay(true)?;
        if let Some(tls)=consent.backend_tls.clone() {
            let target=tokio::select! {biased;
                _=shared.stopped()=>return Ok(()),
                result=tokio::time::timeout(Duration::from_secs(2),tls.connect(target))=>result.map_err(|_|SdkError::Timeout)??,
            };
            forward(shared.clone(),stream,target).await
        } else {forward(shared.clone(),stream,target).await}
    }.await;
    connection.close(0u32.into(), b"offline private flow ended");
    result
}
fn record(
    report: &mut OfflinePrivateReport,
    outcome: Option<Result<FlowOutcome, tokio::task::JoinError>>,
) {
    report.completed_connections += 1;
    match outcome {
        Some(Ok(outcome)) => {
            report.released_quic_sockets += u64::from(outcome.released);
            report.failed_connections += u64::from(outcome.failed);
            report.cleanup_failures += u64::from(outcome.cleanup_failed);
        }
        _ => report.cleanup_failures += 1,
    }
}
async fn run_host(
    shared: Arc<Shared>,
    host: Arc<DeviceIdentity>,
    consent: Arc<LocalServiceTargetConsent>,
    listener: PrivateListener,
) -> OfflinePrivateReport {
    let mut report = OfflinePrivateReport {
        local_endpoint_removed: true,
        ..Default::default()
    };
    let mut workers = JoinSet::new();
    loop {
        tokio::select! {biased;
            _=shared.stopped()=>break,
            result=workers.join_next(),if !workers.is_empty()=>record(&mut report,result),
            incoming=listener.endpoint.accept()=>{
                let Some(incoming)=incoming else {break;};
                if workers.len()>=MAX_FLOWS {incoming.refuse();report.rejected_connections+=1;continue;}
                report.accepted_connections+=1;
                let (shared,host,consent)=(shared.clone(),host.clone(),consent.clone());
                workers.spawn(async move {FlowOutcome {failed:host_flow(shared,host,consent,incoming).await.is_err(),..Default::default()}});
            }
        }
    }
    shared.stop();
    listener
        .endpoint
        .close(0u32.into(), b"offline host stopped");
    while !workers.is_empty() {
        record(&mut report, workers.join_next().await);
    }
    if listener.close_and_wait().await.is_ok() {
        report.released_quic_sockets += 1;
    } else {
        report.cleanup_failures += 1;
    }
    report
}
pub(super) async fn proxy(
    sdk: &Arc<Sdk>,
    consumer: Arc<DeviceIdentity>,
    consumed: ConsumedOfflineBundle,
    peer: SocketAddr,
    private_directory: &Path,
) -> Result<OfflinePrivateRuntime, SdkError> {
    if peer.port() == 0
        || peer.ip().is_unspecified()
        || peer.ip().is_multicast()
        || consumed.claims().deployment_id != sdk.trust.deployment_id
        || !consumed
            .claims()
            .connection
            .direct_transports
            .contains(&OfflineDirectTransport::Quic)
    {
        return Err(SdkError::Invalid);
    }
    let shared = Shared::new(consumed, &consumer, 0)?;
    let listener = Listener::bind(private_directory, &random_id())?;
    let endpoint = listener.endpoint().to_path_buf();
    let monitor = tokio::spawn(recovery_monitor(shared.clone(), sdk.clone()));
    let owner = shared.clone();
    let task = tokio::spawn(async move {
        let report = run_proxy(owner, consumer, peer, listener).await;
        monitor.abort();
        let _ = monitor.await;
        report
    });
    Ok(OfflinePrivateRuntime {
        shared,
        address: None,
        endpoint: Some(endpoint),
        task: Some(task),
        report: None,
        runtime: tokio::runtime::Handle::current(),
    })
}
async fn source_flow<S: AsyncRead + AsyncWrite + Unpin>(
    shared: Arc<Shared>,
    consumer: Arc<DeviceIdentity>,
    peer: SocketAddr,
    local: S,
) -> FlowOutcome {
    let key = match shared.lock() {
        Ok(mut state) => {
            if state
                .authority
                .reserve_connection_attempt(wall().unwrap_or(0), OfflineDirectTransport::Quic)
                .is_err()
            {
                return FlowOutcome {
                    failed: true,
                    ..Default::default()
                };
            }
            state.authority.claims().members[1].public_key
        }
        Err(_) => {
            return FlowOutcome {
                failed: true,
                cleanup_failed: true,
                ..Default::default()
            };
        }
    };
    let connected = match carrier::connect_cancellable(
        peer,
        &consumer.identity,
        digest(&key),
        shared.stopped(),
    )
    .await
    {
        Ok(owner) => owner,
        Err(_) => {
            return FlowOutcome {
                failed: true,
                cleanup_failed: true,
                ..Default::default()
            };
        }
    };
    let result=async {
        let stream=tokio::select! {biased;
            _=shared.stopped()=>return Ok(()),
            result=tokio::time::timeout(Duration::from_secs(2),source_proof(&shared,&consumer,&connected.connection))=>result.map_err(|_|SdkError::Timeout)??,
        };
        forward(shared.clone(),stream,local).await
    }.await;
    let released = connected.close_and_wait().await.is_ok();
    FlowOutcome {
        failed: result.is_err(),
        released,
        cleanup_failed: !released,
    }
}
async fn run_proxy(
    shared: Arc<Shared>,
    consumer: Arc<DeviceIdentity>,
    peer: SocketAddr,
    mut listener: Listener,
) -> OfflinePrivateReport {
    let mut report = OfflinePrivateReport::default();
    let mut workers = JoinSet::new();
    loop {
        tokio::select! {biased;
            _=shared.stopped()=>break,
            result=workers.join_next(),if !workers.is_empty()=>record(&mut report,result),
            incoming=listener.accept()=>{
                let local=match incoming {Ok(s)=>s,Err(e) if e.kind()==io::ErrorKind::PermissionDenied=>{report.rejected_connections+=1;continue;},Err(_)=>{report.cleanup_failures+=1;break;}};
                if workers.len()>=MAX_FLOWS {drop(local);report.rejected_connections+=1;continue;}
                report.accepted_connections+=1;
                let (shared,consumer)=(shared.clone(),consumer.clone());
                workers.spawn(async move {source_flow(shared,consumer,peer,local).await});
            }
        }
    }
    listener.stop_accepting();
    shared.stop();
    while !workers.is_empty() {
        record(&mut report, workers.join_next().await);
    }
    report.local_endpoint_removed = listener.cleanup().is_ok();
    if !report.local_endpoint_removed {
        report.cleanup_failures += 1;
    }
    report
}
