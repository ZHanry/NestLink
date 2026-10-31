//! Native private services retain original consent, the shared durable meter,
//! current management authorization and physical Quinn socket owners.
use super::*;
use nestlink_identity::{
    digest,
    services::private::{verify_private_service_open, verify_private_service_ready},
};
use nestlink_node::{
    service_plane::{
        DatagramMapping, DatagramPacket, DatagramReply, LocalTargetOwner,
        PrivateServicePublication, PublicationContext, ServiceDatagramReplayWindow,
    },
    service_usage::ServiceUsageStore,
};
use nestlink_protocol::service_plane::{
    SERVICE_USAGE_BYTES, ServiceUsageBudgetGrantClaims, decode_service_message,
};
use nestlink_transport_quic::service::{
    self as carrier, BiStream, PrivateListener, read_message, write_message,
};
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    sync::watch,
    task::{JoinHandle, JoinSet},
};

pub struct PrivateServiceHostConfig {
    pub listen: SocketAddr,
    /// A host-selected reachable address for the inner service listener.
    pub advertised_ip: std::net::IpAddr,
    pub usage_directory: PathBuf,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Hello {
    service_id: String,
    grant_id: String,
}

pub struct PrivateServiceHost {
    address: SocketAddr,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<Result<(), SdkError>>>,
    runtime: tokio::runtime::Handle,
    failed: bool,
    cleanup_deadline: std::sync::Mutex<Option<tokio::time::Instant>>,
}
impl PrivateServiceHost {
    pub fn address(&self) -> SocketAddr {
        self.address
    }
    pub fn stop(&self) {
        if let Ok(mut deadline) = self.cleanup_deadline.lock() {
            deadline.get_or_insert(tokio::time::Instant::now() + Duration::from_secs(5));
        }
        self.stop.send_replace(true);
    }
    /// Cancellation retains the original join handle. Success includes every
    /// connection worker and the real UDP socket/poller completion receipt.
    pub async fn wait_stopped(&mut self) -> Result<(), SdkError> {
        self.stop();
        let Some(task) = self.task.as_mut() else {
            return if self.failed {
                Err(SdkError::Trust)
            } else {
                Ok(())
            };
        };
        let deadline = self
            .cleanup_deadline
            .lock()
            .map_err(|_| SdkError::Trust)?
            .ok_or(SdkError::Trust)?;
        let result = match tokio::time::timeout_at(deadline, &mut *task).await {
            Err(_) => return Err(SdkError::Timeout),
            Ok(result) => result.map_err(|_| SdkError::Trust).and_then(|r| r),
        };
        self.task.take();
        self.failed = result.is_err();
        result
    }
}
impl Drop for PrivateServiceHost {
    fn drop(&mut self) {
        self.stop();
        if let Some(task) = self.task.take() {
            self.runtime.spawn(async move {
                let _ = task.await;
            });
        }
    }
}

pub struct PrivateServiceConnection {
    connected: Option<carrier::Connected>,
    stream: Option<BiStream>,
    lease: VerifiedPrivateServiceLease,
    udp_sequence: u64,
    replies: ServiceDatagramReplayWindow,
    runtime: tokio::runtime::Handle,
    closing: Option<JoinHandle<std::io::Result<()>>>,
}
impl PrivateServiceConnection {
    /// This stream carries bytes for the one locally approved TCP/HTTP target.
    pub fn stream(&mut self) -> Result<&mut BiStream, SdkError> {
        if matches!(
            self.lease.lease().claims().definition.requested_ingress,
            ServiceIngress::Udp { .. }
        ) {
            return Err(SdkError::Invalid);
        }
        self.lease.check_time(private_wall_ms()?)?;
        self.stream.as_mut().ok_or(SdkError::Trust)
    }
    pub fn lease(&self) -> &VerifiedPrivateServiceLease {
        &self.lease
    }
    pub fn send_datagram(&mut self, payload: &[u8]) -> Result<(), SdkError> {
        if !matches!(
            self.lease.lease().claims().definition.requested_ingress,
            ServiceIngress::Udp { .. }
        ) {
            return Err(SdkError::Invalid);
        }
        self.lease.check_time(private_wall_ms()?)?;
        self.udp_sequence = self.udp_sequence.checked_add(1).ok_or(SdkError::Invalid)?;
        let packet = DatagramPacket {
            mapping_id: self.lease.lease().claims().publication_id.clone(),
            sequence: self.udp_sequence,
            payload: payload.into(),
        }
        .encode()?;
        carrier::datagram::send(
            &self.connected.as_ref().ok_or(SdkError::Trust)?.connection,
            packet,
        )?;
        Ok(())
    }
    pub async fn receive_datagram(&mut self) -> Result<Vec<u8>, SdkError> {
        if !matches!(
            self.lease.lease().claims().definition.requested_ingress,
            ServiceIngress::Udp { .. }
        ) {
            return Err(SdkError::Invalid);
        }
        loop {
            self.lease.check_time(private_wall_ms()?)?;
            let remaining = self
                .lease
                .lease()
                .claims()
                .expires_at_unix_ms
                .saturating_sub(private_wall_ms()?);
            let packet = tokio::time::timeout(
                Duration::from_millis(remaining),
                self.connected
                    .as_ref()
                    .ok_or(SdkError::Trust)?
                    .connection
                    .read_datagram(),
            )
            .await
            .map_err(|_| SdkError::Timeout)?
            .map_err(std::io::Error::other)?;
            let Ok(reply) = DatagramReply::decode(&packet) else {
                continue;
            };
            if reply.mapping_id == self.lease.lease().claims().publication_id
                && self.replies.accept(reply.sequence).is_ok()
            {
                return Ok(reply.payload);
            }
        }
    }
    pub async fn close(&mut self) -> Result<(), SdkError> {
        self.stream.take();
        if let Some(connected) = self.connected.take() {
            self.closing = Some(self.runtime.spawn(connected.close_and_wait()));
        }
        if let Some(task) = self.closing.as_mut() {
            let result = task.await.map_err(|_| SdkError::Trust);
            self.closing.take();
            result??;
        }
        Ok(())
    }
}
impl Drop for PrivateServiceConnection {
    fn drop(&mut self) {
        self.stream.take();
        if let Some(connected) = self.connected.take() {
            connected
                .connection
                .close(0u32.into(), b"private consumer dropped");
            self.runtime.spawn(async move {
                let _ = connected.close_and_wait().await;
            });
        }
        if let Some(task) = self.closing.take() {
            self.runtime.spawn(async move {
                let _ = task.await;
            });
        }
    }
}

impl Sdk {
    pub async fn start_private_service_host(
        self: &Arc<Self>,
        host: Arc<DeviceIdentity>,
        consent: LocalServiceTargetConsent,
        config: PrivateServiceHostConfig,
    ) -> Result<PrivateServiceHost, SdkError> {
        if host.device_id != consent.host_device_id
            || self.principal().ok_or(SdkError::SignIn)?.account_id != consent.account_id
            || config.advertised_ip.is_unspecified()
            || config.advertised_ip.is_multicast()
            || (consent.protocol == "https" && consent.backend_tls.is_none())
        {
            return Err(SdkError::Invalid);
        }
        let view = self.service(&consent.service_id).await?;
        let exposure = self
            .service_exposure(&consent.service_id)
            .await?
            .ok_or(SdkError::Trust)?;
        if view.revision != consent.revision.checked_add(1).ok_or(SdkError::Invalid)?
            || view.approval != ServiceApprovalState::ApprovedTarget
            || !exposure.mode.private_enabled()
            || exposure.service_revision != view.revision
            || view.definition != consent.original_view.definition
            || view.target_id.as_deref() != Some(consent.target_id.as_str())
            || view.target_sha256.as_deref() != Some(consent.target_sha256.as_str())
        {
            return Err(SdkError::Trust);
        }
        let approved_until = view
            .approval_expires_at_unix_ms
            .filter(|end| *end > private_wall_ms().unwrap_or(u64::MAX))
            .ok_or(SdkError::Trust)?;
        let usage =
            Arc::new(ServiceUsageStore::open(&config.usage_directory).map_err(usage_error)?);
        let policy = self.policy().await?;
        let listener =
            PrivateListener::bind(config.listen, &host.identity).map_err(SdkError::NodeQuic)?;
        let address = SocketAddr::new(config.advertised_ip, listener.endpoint.local_addr()?.port());
        let runtime_id = random_id();
        let claims = PrivateServiceHostClaims {
            schema_version: nestlink_protocol::SCHEMA_VERSION,
            deployment_id: self.trust.deployment_id.clone(),
            security_epoch: self.health.security_epoch,
            policy_revision: policy.revision,
            service_id: view.id,
            service_revision: view.revision,
            exposure_revision: exposure.revision,
            target_sha256: exposure.target_sha256,
            host_device_id: host.device_id.clone(),
            runtime_id,
            request_sequence: 1,
            address: address.to_string(),
            issued_at_unix_ms: 1,
            // Retain the original local approval deadline for every refresh.
            // register signs only its remaining bounded presence interval.
            expires_at_unix_ms: approved_until,
        };
        if let Err(error) = register(self, &host, &claims).await {
            listener.close_and_wait().await?;
            return Err(error);
        }
        let (stop, stopped) = watch::channel(false);
        let task = tokio::spawn(run_host(
            self.clone(),
            host,
            Arc::new(consent),
            claims,
            listener,
            usage,
            stopped,
        ));
        Ok(PrivateServiceHost {
            address,
            stop,
            task: Some(task),
            runtime: tokio::runtime::Handle::current(),
            failed: false,
            cleanup_deadline: std::sync::Mutex::new(None),
        })
    }
    pub async fn connect_private_service(
        &self,
        consumer: &DeviceIdentity,
        lease: VerifiedPrivateServiceLease,
    ) -> Result<PrivateServiceConnection, SdkError> {
        let grant = usage_claims(&lease)?;
        let current = self
            .current_private_service(&grant.service_id, &grant.grant_id)
            .await?;
        if current.digest() != lease.digest()
            || consumer.device_id != lease.claims().consumer_device_id
            || consumer.identity.public_key() != lease.claims().consumer_public_key
        {
            return Err(SdkError::Trust);
        }
        let connected = carrier::connect(
            lease
                .lease()
                .claims()
                .edge_service_address
                .parse()
                .map_err(|_| SdkError::Trust)?,
            &consumer.identity,
            digest(&lease.claims().host_public_key),
        )
        .await
        .map_err(SdkError::NodeQuic)?;
        let result = tokio::time::timeout(Duration::from_secs(3), async {
            let (mut send, mut recv) = connected
                .connection
                .open_bi()
                .await
                .map_err(std::io::Error::other)?;
            write_message(
                &mut send,
                &Hello {
                    service_id: grant.service_id,
                    grant_id: grant.grant_id,
                },
            )
            .await?;
            let nonce: [u8; 32] = read_message(&mut recv).await?;
            let open = consumer.identity.private_service_open(&lease, nonce)?;
            write_message(&mut send, &open).await?;
            let ready: PrivateServiceReady = read_message(&mut recv).await?;
            verify_private_service_ready(&lease, &open, &ready)?;
            Ok::<_, SdkError>(BiStream::new(send, recv))
        })
        .await;
        let stream = match result {
            Ok(Ok(stream)) => stream,
            other => {
                connected.close_and_wait().await?;
                return Err(match other {
                    Ok(Err(e)) => e,
                    _ => SdkError::Timeout,
                });
            }
        };
        Ok(PrivateServiceConnection {
            connected: Some(connected),
            stream: Some(stream),
            lease,
            udp_sequence: 0,
            replies: ServiceDatagramReplayWindow::default(),
            runtime: tokio::runtime::Handle::current(),
            closing: None,
        })
    }
}
fn usage_error(error: nestlink_node::service_usage::Error) -> SdkError {
    SdkError::ServiceIo(std::io::Error::other(error))
}
fn usage_claims(
    lease: &VerifiedPrivateServiceLease,
) -> Result<ServiceUsageBudgetGrantClaims, SdkError> {
    Ok(decode_service_message(
        &lease.lease().claims().usage_grant.claims,
        SERVICE_USAGE_BYTES,
    )?)
}
async fn register(
    sdk: &Sdk,
    host: &DeviceIdentity,
    base: &PrivateServiceHostClaims,
) -> Result<(), SdkError> {
    let mut claims = base.clone();
    claims.issued_at_unix_ms = private_wall_ms()?;
    claims.expires_at_unix_ms = claims
        .issued_at_unix_ms
        .checked_add(nestlink_protocol::service_plane::SERVICE_LEASE_MS)
        .ok_or(SdkError::Invalid)?
        .min(base.expires_at_unix_ms);
    tokio::time::timeout(
        Duration::from_secs(1),
        sdk.register_private_service_host(
            &claims.service_id,
            &host.identity.sign_private_service_host(&claims)?,
        ),
    )
    .await
    .map_err(|_| SdkError::Timeout)?
}
async fn stopped(stop: &mut watch::Receiver<bool>) {
    loop {
        if *stop.borrow() || stop.changed().await.is_err() {
            return;
        }
    }
}
#[allow(clippy::too_many_arguments)]
async fn run_host(
    sdk: Arc<Sdk>,
    host: Arc<DeviceIdentity>,
    consent: Arc<LocalServiceTargetConsent>,
    mut presence: PrivateServiceHostClaims,
    listener: PrivateListener,
    usage: Arc<ServiceUsageStore>,
    mut stop: watch::Receiver<bool>,
) -> Result<(), SdkError> {
    let mut workers = JoinSet::new();
    let mut refresh = tokio::time::interval(Duration::from_secs(5));
    refresh.tick().await;
    let deadline = tokio::time::Instant::now()
        + Duration::from_millis(
            presence
                .expires_at_unix_ms
                .saturating_sub(private_wall_ms().unwrap_or(u64::MAX)),
        );
    let mut failed = false;
    loop {
        tokio::select! {biased;
            _=stopped(&mut stop)=>break,
            _=tokio::time::sleep_until(deadline)=>break,
            _=refresh.tick()=>{
                let Some(next)=presence.request_sequence.checked_add(1) else {failed=true;break;};
                presence.request_sequence=next;
                let registered=tokio::select!{biased;
                    _=stopped(&mut stop)=>break,
                    _=tokio::time::sleep_until(deadline)=>break,
                    result=register(&sdk,&host,&presence)=>result,
                };
                if registered.is_err() {failed=true;break;}
                let pending=usage.private_report_targets(&host.identity,&presence.runtime_id).map_err(usage_error);
                if let Ok(pending)=pending {
                    for (grant,terminal)in pending {tokio::select!{biased;
                        _=stopped(&mut stop)=>break,
                        _=tokio::time::sleep_until(deadline)=>break,
                        _=flush_report(&sdk,&usage,&host,&grant,terminal)=>{},
                    }}
                }else{failed=true;break;}
            },
            joined=workers.join_next(),if !workers.is_empty()=>{if matches!(joined,Some(Err(_)|Ok(Err(_)))){failed=true;}},
            incoming=listener.endpoint.accept()=>{
                let Some(incoming)=incoming else{break;};
                if workers.len()>=128 {incoming.refuse();continue;}
                workers.spawn(serve_connection(sdk.clone(),host.clone(),consent.clone(),presence.clone(),usage.clone(),stop.clone(),incoming));
            }
        }
    }
    listener
        .endpoint
        .close(0u32.into(), b"private service stopping");
    let mut withdrawal = presence.clone();
    withdrawal.request_sequence = withdrawal.request_sequence.saturating_add(1);
    withdrawal.issued_at_unix_ms = private_wall_ms().unwrap_or(u64::MAX);
    withdrawal.expires_at_unix_ms = withdrawal
        .issued_at_unix_ms
        .saturating_add(nestlink_protocol::service_plane::SERVICE_LEASE_MS);
    if let Ok(signed) = host.identity.withdraw_private_service_host(&withdrawal) {
        if !matches!(
            tokio::time::timeout(
                Duration::from_secs(1),
                sdk.withdraw_private_service_host(&withdrawal.service_id, &signed)
            )
            .await,
            Ok(Ok(()))
        ) {
            failed = true;
        }
    } else {
        failed = true;
    }
    while let Some(joined) = workers.join_next().await {
        if !matches!(joined, Ok(Ok(()))) {
            failed = true;
        }
    }
    listener.close_and_wait().await?;
    if failed {
        return Err(SdkError::Trust);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn serve_connection(
    sdk: Arc<Sdk>,
    host: Arc<DeviceIdentity>,
    consent: Arc<LocalServiceTargetConsent>,
    presence: PrivateServiceHostClaims,
    usage: Arc<ServiceUsageStore>,
    mut stop: watch::Receiver<bool>,
    incoming: quinn::Incoming,
) -> Result<(), SdkError> {
    let handshake = tokio::time::timeout(Duration::from_secs(3), async {
        let connection = incoming.await.map_err(std::io::Error::other)?;
        if !carrier::negotiated_service(&connection) {
            return Err(SdkError::Trust);
        }
        let (mut send, mut recv) = connection
            .accept_bi()
            .await
            .map_err(std::io::Error::other)?;
        let hello: Hello = read_message(&mut recv).await?;
        if hello.service_id != presence.service_id || !valid_id(&hello.grant_id) {
            return Err(SdkError::Trust);
        }
        let lease = sdk
            .current_private_service(&hello.service_id, &hello.grant_id)
            .await?;
        if lease.lease().claims().edge_runtime_id != presence.runtime_id {
            return Err(SdkError::Trust);
        }
        let nonce = random_bytes::<32>();
        write_message(&mut send, &nonce).await?;
        let open: PrivateServiceOpen = read_message(&mut recv).await?;
        if open.nonce != nonce {
            return Err(SdkError::Trust);
        }
        verify_private_service_open(&lease, &open)?;
        Ok::<_, SdkError>((connection, send, recv, lease, open, nonce))
    });
    let admitted = tokio::select! {biased;
        _=stopped(&mut stop)=>return Ok(()),
        result=handshake=>result,
    };
    // Unauthenticated/mismatched socket attempts are ordinary refusals. Once
    // a durable publication activates, every cleanup/report error is retained.
    let Ok(Ok((connection, send, recv, lease, open, nonce))) = admitted else {
        return Ok(());
    };
    let _connection_close = ConnectionClose(connection.clone());
    let context = PublicationContext {
        deployment_id: presence.deployment_id.clone(),
        security_epoch: presence.security_epoch,
        policy_revision: presence.policy_revision,
        service_lease_issuer: lease.lease().issuer(),
    };
    let target = LocalTargetOwner::from_local_choice(
        context.clone(),
        consent.original_view.clone(),
        consent.target_id.clone(),
        consent.protocol.clone(),
        consent.address,
        host.identity.public_key(),
    )?;
    let ready = host.identity.private_service_ready(&lease, &open)?;
    let grant = usage_claims(&lease)?;
    let publication =
        PrivateServicePublication::new(lease.clone(), &context, Instant::now(), usage.clone())?;
    let mut stream = BiStream::new(send, recv);
    let forward = async {
        let prepared = publication.prepare(&target, &open, nonce, &host.identity)?;
        write_message(stream.parts_mut().0, &ready).await?;
        if consent.protocol == "udp" {
            forward_udp(prepared, &mut stream, &connection).await
        } else if let Some(tls) = consent.backend_tls.clone() {
            prepared
                .forward_https(&mut stream, move |socket| tls.connect(socket))
                .await?;
            Ok(())
        } else {
            prepared.forward_stream(&mut stream).await?;
            Ok(())
        }
    };
    let monitor = async {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            let current = sdk
                .current_private_service(&grant.service_id, &grant.grant_id)
                .await?;
            if current.digest() != lease.digest() {
                return Err::<(), SdkError>(SdkError::Trust);
            }
            flush_report(&sdk, &usage, &host, &grant.grant_id, false).await?;
        }
    };
    let completed = tokio::select! {biased;
        _=stopped(&mut stop)=>false,
        _=connection.closed()=>false,
        _=monitor=>false,
        result=forward=>result.is_ok(),
    };
    publication.revoke();
    target.revoke();
    if completed && consent.protocol != "udp" {
        let _ = tokio::time::timeout(Duration::from_secs(3), stream.wait_finished()).await;
    }
    drop(stream);
    connection.close(0u32.into(), b"private grant ended");
    let token = publication.handle().wait_drained().await?;
    usage.confirm_drained(&token).map_err(usage_error)?;
    // A pending ordinary report is acknowledged first, then the final seal.
    for _ in 0..2 {
        if flush_report(&sdk, &usage, &host, &grant.grant_id, true).await? {
            break;
        }
    }
    Ok(())
}
async fn flush_report(
    sdk: &Sdk,
    usage: &ServiceUsageStore,
    host: &DeviceIdentity,
    grant: &str,
    terminal: bool,
) -> Result<bool, SdkError> {
    let Some(report) = usage
        .private_report(grant, &host.identity, terminal, private_wall_ms()?)
        .map_err(usage_error)?
    else {
        return Ok(true);
    };
    let ack = tokio::time::timeout(
        Duration::from_secs(1),
        sdk.report_private_service_usage(&report),
    )
    .await
    .map_err(|_| SdkError::Timeout)??;
    usage
        .acknowledge_private_report(&ack)
        .map_err(usage_error)?;
    Ok(ack.terminal)
}
struct ConnectionClose(quinn::Connection);
impl Drop for ConnectionClose {
    fn drop(&mut self) {
        self.0.close(0u32.into(), b"private connection owner ended");
    }
}
async fn forward_udp(
    prepared: nestlink_node::service_plane::PreparedPrivateLocalTunnel,
    control: &mut BiStream,
    connection: &quinn::Connection,
) -> Result<(), SdkError> {
    let mapping = DatagramMapping::new_private(prepared).await?;
    let router = carrier::datagram::DatagramRouter::new();
    let packets = router.register(DatagramPacket::mapping_key(mapping.mapping_id())?)?;
    tokio::select! {biased;
        result=router.drive(connection,false)=>{result?;Ok(())},
        result=super::super::publication::datagram::forward_mapping(mapping,control,connection,packets)=>result,
    }
}
