//! Native host runtime retains the original local choice. Neither management
//! JSON nor a visitor stream can replace the approved socket address.
use super::*;
use nestlink_identity::service_plane::{
    VerifiedServiceLease, publication::verify_service_issuer_delegation,
};
use nestlink_node::service_plane::{LocalTargetOwner, PublicationContext, ServicePublication};
use nestlink_protocol::service_plane::{publication::*, *};
use nestlink_transport_quic::service::{self as carrier, BiStream, read_message, write_message};
use std::{
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::watch, task::JoinSet};
mod backend_tls;
mod cleanup;
mod datagram;
pub use backend_tls::HttpsBackendTls;
use carrier::datagram::DatagramRouter;
mod issuer;
use cleanup::ServiceCleanupMonitor;
use issuer::ServiceIssuerOwner;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceHostStopReport {
    pub failed: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceHostWait {
    CleanupPending { failed: bool },
    Stopped(ServiceHostStopReport),
}

fn wall() -> Result<u64, SdkError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SdkError::Trust)?
        .as_millis()
        .try_into()
        .map_err(|_| SdkError::Trust)
}
pub struct LocalServiceRuntime {
    publication: Arc<ServicePublication>,
    target: Arc<LocalTargetOwner>,
    connection: quinn::Connection,
    stop: watch::Sender<bool>,
    cleanup: ServiceCleanupMonitor,
}
impl LocalServiceRuntime {
    pub fn stop(&self) {
        self.stop.send_replace(true);
        self.target.revoke();
        self.publication.revoke();
        self.connection.close(0u32.into(), b"local service stopped");
    }
    pub fn publication_id(&self) -> Result<String, SdkError> {
        Ok(self
            .publication
            .handle()
            .lease()?
            .claims()
            .publication_id
            .clone())
    }
    pub fn counters(&self) -> Result<nestlink_node::meter::Counters, SdkError> {
        Ok(self.publication.handle().counters()?)
    }
    pub fn cleanup_pending(&self) -> bool {
        self.cleanup.pending()
            && (*self.stop.borrow() || self.publication.handle().lease().is_err())
    }
    /// Timeout or abandonment leaves the same handle and endpoint owned here.
    /// Only Stopped certifies the worker, every flow task and QUIC endpoint ended.
    pub async fn wait_stopped(&mut self, budget: Duration) -> ServiceHostWait {
        self.stop();
        self.cleanup.wait(budget).await
    }
}
impl Drop for LocalServiceRuntime {
    fn drop(&mut self) {
        self.stop();
    }
}
struct Revoke {
    publication: Arc<ServicePublication>,
    target: Arc<LocalTargetOwner>,
    connection: quinn::Connection,
}
impl Drop for Revoke {
    fn drop(&mut self) {
        self.target.revoke();
        self.publication.revoke();
        self.connection
            .close(0u32.into(), b"local service authority ended");
    }
}
impl Sdk {
    /// Consumes local consent so it cannot be silently reused by a second host
    /// owner. `host` is the same installation identity that signed target consent.
    pub async fn start_service_host(
        &self,
        host: Arc<DeviceIdentity>,
        consent: LocalServiceTargetConsent,
    ) -> Result<LocalServiceRuntime, SdkError> {
        let (_keep, cancelled) = watch::channel(false);
        self.start_service_host_cancellable(host, consent, cancelled)
            .await
    }
    /// Cancellation returns Interrupted only after the same local target,
    /// publication, connection and endpoint have been revoked and drained.
    /// The caller keeps awaiting this future after sending true. Ownership
    /// transfers to LocalServiceRuntime on success; later stops use that handle.
    pub async fn start_service_host_cancellable(
        &self,
        host: Arc<DeviceIdentity>,
        consent: LocalServiceTargetConsent,
        mut cancelled: watch::Receiver<bool>,
    ) -> Result<LocalServiceRuntime, SdkError> {
        if *cancelled.borrow() {
            return Err(interrupted());
        }
        let principal = self.principal().ok_or(SdkError::SignIn)?;
        if host.device_id != consent.host_device_id || principal.account_id != consent.account_id {
            return Err(SdkError::Trust);
        }
        if consent.protocol == "https" && consent.backend_tls.is_none() {
            return Err(SdkError::Invalid);
        }
        let revision = consent.revision.checked_add(1).ok_or(SdkError::Invalid)?;
        let requested = Instant::now();
        let grant_path = format!("{}/publication", resource("services", &consent.service_id)?);
        let grant_request = ServicePublicationRequest {
            expected_revision: revision,
        };
        let grant: ServicePublicationGrant = tokio::select! {biased;
            _=start_cancelled(&mut cancelled)=>return Err(interrupted()),
            grant=self
            .required(
                Method::POST,
                &grant_path,
                Some(&grant_request),
            )
            =>grant?,
        };
        let policy: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&self.health.node_policy_issuer)
            .map_err(|_| SdkError::Trust)?
            .try_into()
            .map_err(|_| SdkError::Trust)?;
        let delegation = Arc::new(ServiceIssuerOwner::new(verify_service_issuer_delegation(
            &grant.issuer,
            &policy,
            &self.trust.deployment_id,
            wall()?,
        )?));
        let lease = delegation.verify_lease(&grant.lease, wall()?)?;
        let c = lease.claims();
        if c.security_epoch != self.health.security_epoch
            || c.service_revision != revision
            || c.account_id != principal.account_id
            || c.edge_key_sha256 != digest(&grant.edge_public_key)
        {
            return Err(SdkError::Trust);
        }
        let context = PublicationContext {
            deployment_id: c.deployment_id.clone(),
            security_epoch: c.security_epoch,
            policy_revision: c.policy_revision,
            service_lease_issuer: lease.issuer(),
        };
        let target = Arc::new(LocalTargetOwner::from_local_choice(
            context.clone(),
            consent.original_view,
            consent.target_id,
            consent.protocol,
            consent.address,
            host.identity.public_key(),
        )?);
        let backend_tls = consent.backend_tls;
        if !target.accepts(&lease) {
            return Err(SdkError::Trust);
        }
        let address = service_socket(&c.edge_service_address)?;
        let publication = Arc::new(ServicePublication::new(lease.clone(), &context, requested)?);
        let connected = match carrier::connect(address, &host.identity, c.edge_key_sha256).await {
            Ok(connected) => connected,
            Err(error) => {
                target.revoke();
                publication.revoke();
                return Err(if *cancelled.borrow() {
                    interrupted()
                } else {
                    SdkError::NodeQuic(error)
                });
            }
        };
        let revoke = Revoke {
            publication: publication.clone(),
            target: target.clone(),
            connection: connected.connection.clone(),
        };
        let prepare = async {
            if matches!(c.definition.requested_ingress, ServiceIngress::Udp { .. })
                && !carrier::datagram::supports_native(&connected.connection)
            {
                return Err(SdkError::ServiceIo(std::io::ErrorKind::Unsupported.into()));
            }
            let began = Instant::now();
            let (control_send, mut control_recv, attached_digest) =
                tokio::time::timeout(Duration::from_secs(2), async {
                    let (mut send, mut recv) = connected
                        .connection
                        .open_bi()
                        .await
                        .map_err(|e| SdkError::ServiceIo(std::io::Error::other(e)))?;
                    write_message(
                        &mut send,
                        &ServiceHostIntroduction {
                            publication_id: c.publication_id.clone(),
                            generation: c.publication_generation,
                            host_public_key: host.identity.public_key(),
                        },
                    )
                    .await?;
                    let offer: ServiceAttachmentOffer = read_message(&mut recv).await?;
                    let attached = delegation.verify_lease(&offer.lease, wall()?)?;
                    renew(&publication, attached.clone(), began)?;
                    if !target.accepts(&attached) {
                        return Err(SdkError::Trust);
                    }
                    let proof = host.identity.prove_service_attachment(
                        &attached,
                        &offer.challenge,
                        &grant.edge_public_key,
                        target.runtime_id(),
                        wall()?,
                    )?;
                    write_message(&mut send, &proof).await?;
                    Ok::<_, SdkError>((send, recv, attached.digest()))
                })
                .await
                .map_err(|_| SdkError::Timeout)??;
            let web = matches!(
                c.definition.requested_ingress,
                ServiceIngress::Http { .. } | ServiceIngress::Https { .. }
            );
            let ready_budget = if web {
                Duration::from_secs(90)
            } else {
                Duration::from_secs(2).saturating_sub(began.elapsed())
            };
            tokio::time::timeout(ready_budget,async {
            let mut tick=tokio::time::interval(Duration::from_millis(25));
            loop {
                // read_message consumes a length prefix and is not cancellation
                // safe. Keep the same future across authority timer ticks.
                let next=read_message::<ServiceAttachmentStatus>(&mut control_recv);
                tokio::pin!(next);
                let status=loop {
                    tokio::select! {biased;
                        _=connected.connection.closed()=>return Err(SdkError::Trust),
                        _=tick.tick()=>{publication.handle().lease()?;delegation.check_live(wall()?)?;},
                        status=&mut next=>break status?,
                    }
                };
                match status {
                    ServiceAttachmentStatus::Renewal(signed) if web=>{
                        let requested=Instant::now();let candidate=delegation.prepare(&signed,wall()?)?;
                        if !target.accepts(&candidate.lease){return Err(SdkError::Trust);}
                        renew(&publication,candidate.lease,requested)?;
                        delegation.install(candidate.issuer)?;
                    },
                    ServiceAttachmentStatus::Renewal(_)=>return Err(SdkError::Trust),
                    ServiceAttachmentStatus::Ready(ready)=>{
                        if ready.publication_id!=c.publication_id || ready.generation!=c.publication_generation
                            || ready.host_runtime_id!=target.runtime_id() || ready.lease_sha256!=attached_digest {
                            return Err(SdkError::Trust);
                        }
                        publication.handle().lease()?;delegation.check_live(wall()?)?;
                        return Ok(());
                    },
                }
            }
        }).await.map_err(|_|SdkError::Timeout)??;
            Ok::<_, SdkError>((control_send, control_recv))
        };
        let prepared = tokio::select! {biased;
            _=start_cancelled(&mut cancelled)=>Err(interrupted()),
            prepared=prepare=>prepared,
        };
        let (control_send, control_recv) = match prepared {
            Ok(streams) => streams,
            Err(error) => {
                target.revoke();
                publication.revoke();
                // Revoke owns a connection clone. Release it before awaiting
                // the actual UDP driver's socket/poller completion.
                drop(revoke);
                connected
                    .close_and_wait()
                    .await
                    .map_err(SdkError::ServiceIo)?;
                return Err(error);
            }
        };
        let connection = connected.connection.clone();
        let (stop, stopped) = watch::channel(false);
        let endpoint = connected.endpoint.clone();
        let task = tokio::spawn(run(
            RunContext {
                connected,
                host,
                delegation,
                publication: publication.clone(),
                target: target.clone(),
                edge_key: grant.edge_public_key,
                control_send,
                control_recv,
                stop: stopped,
                backend_tls,
            },
            revoke,
        ));
        let cleanup = ServiceCleanupMonitor::new(task, endpoint);
        Ok(LocalServiceRuntime {
            publication,
            target,
            connection,
            stop,
            cleanup,
        })
    }
}
fn interrupted() -> SdkError {
    SdkError::ServiceIo(std::io::ErrorKind::Interrupted.into())
}
async fn start_cancelled(cancelled: &mut watch::Receiver<bool>) {
    loop {
        if *cancelled.borrow() {
            return;
        }
        if cancelled.changed().await.is_err() {
            return;
        }
    }
}
fn renew(
    publication: &ServicePublication,
    lease: VerifiedServiceLease,
    requested: Instant,
) -> Result<(), SdkError> {
    let current = publication.handle().lease()?;
    if current.binding() != lease.binding() || current.issuer() != lease.issuer() {
        return Err(SdkError::Trust);
    }
    if lease.claims().lease_sequence <= current.claims().lease_sequence {
        if lease.claims().lease_sequence == current.claims().lease_sequence
            && lease.digest() != current.digest()
        {
            return Err(SdkError::Trust);
        }
        return Ok(());
    }
    // The independent control and visitor streams can race to install the same
    // newer lease. A concurrently completed valid advance is sufficient.
    if let Err(error) = publication.renew(lease.clone(), requested) {
        let current = publication.handle().lease()?;
        if current.binding() != lease.binding()
            || current.issuer() != lease.issuer()
            || current.claims().lease_sequence < lease.claims().lease_sequence
        {
            return Err(error.into());
        }
    }
    Ok(())
}
struct RunContext {
    connected: carrier::Connected,
    host: Arc<DeviceIdentity>,
    delegation: Arc<ServiceIssuerOwner>,
    publication: Arc<ServicePublication>,
    target: Arc<LocalTargetOwner>,
    edge_key: [u8; 32],
    control_send: quinn::SendStream,
    control_recv: quinn::RecvStream,
    stop: watch::Receiver<bool>,
    backend_tls: Option<HttpsBackendTls>,
}
#[derive(Clone)]
struct ForwardContext {
    host: Arc<DeviceIdentity>,
    delegation: Arc<ServiceIssuerOwner>,
    publication: Arc<ServicePublication>,
    target: Arc<LocalTargetOwner>,
    edge_key: [u8; 32],
    connection: quinn::Connection,
    datagrams: DatagramRouter,
    backend_tls: Option<HttpsBackendTls>,
}
async fn run(context: RunContext, _revoke: Revoke) -> ServiceHostStopReport {
    let RunContext {
        connected,
        host,
        delegation,
        publication,
        target,
        edge_key,
        control_send: _control_send,
        mut control_recv,
        mut stop,
        backend_tls,
    } = context;
    let renew_publication = publication.clone();
    let renew_target = target.clone();
    let renew_delegation = delegation.clone();
    let mut renewals = tokio::spawn(async move {
        loop {
            let requested = Instant::now();
            let signed: ServiceLeaseRenewal = read_message(&mut control_recv).await?;
            let candidate = renew_delegation.prepare(&signed, wall()?)?;
            let lease = candidate.lease;
            if !renew_target.accepts(&lease) {
                return Err(SdkError::Trust);
            }
            renew(&renew_publication, lease, requested)?;
            renew_delegation.install(candidate.issuer)?;
        }
    });
    let mut renewals_joined = false;
    let datagrams = DatagramRouter::new();
    let router = datagrams.clone();
    let datagram_connection = connected.connection.clone();
    let mut datagram_driver =
        tokio::spawn(async move { router.drive(&datagram_connection, false).await });
    let forward_context = ForwardContext {
        host,
        delegation: delegation.clone(),
        publication: publication.clone(),
        target: target.clone(),
        edge_key,
        connection: connected.connection.clone(),
        datagrams: datagrams.clone(),
        backend_tls,
    };
    let mut tasks = JoinSet::new();
    let mut tick = tokio::time::interval(Duration::from_millis(25));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let failed = loop {
        tokio::select! {biased;
            _=stop.changed()=>break false,
            _=connected.connection.closed()=>break true,
            result=&mut renewals=>{renewals_joined=true;break !matches!(result,Ok(Ok(())));},
            _=tick.tick()=>{if publication.handle().lease().is_err()||wall().and_then(|now|delegation.check_live(now)).is_err(){break true;}},
            Some(_)=tasks.join_next()=>{},
            streams=connected.connection.accept_bi()=>{
                let Ok((send,recv))=streams else{break true;};
                let stream=BiStream::new(send,recv);
                if tasks.len()>=SERVICE_MAX_OPENINGS {drop(stream);continue;}
                tasks.spawn(forward(stream,forward_context.clone()));
            },
        }
    };
    target.revoke();
    publication.revoke();
    connected
        .connection
        .close(0u32.into(), b"service host stopping");
    connected
        .endpoint
        .close(0u32.into(), b"service host stopping");
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    datagram_driver.abort();
    let _ = (&mut datagram_driver).await;
    datagrams.close();
    if !renewals_joined {
        renewals.abort();
        let _ = renewals.await;
    }
    // A logical stop is not physical completion. This worker remains alive and
    // owns the endpoint until all QUIC connection tasks have actually ended.
    connected.endpoint.wait_idle().await;
    ServiceHostStopReport { failed }
}
async fn forward(mut stream: BiStream, context: ForwardContext) -> Result<(), SdkError> {
    let began = Instant::now();
    let prepared = tokio::time::timeout(Duration::from_secs(2), async {
        let offer: ServiceStreamOffer = read_message(stream.parts_mut().1).await?;
        let lease = context.delegation.verify_lease(&offer.lease, wall()?)?;
        if !context.target.accepts(&lease) {
            return Err(SdkError::Trust);
        }
        renew(&context.publication, lease.clone(), began)?;
        let prepared = context.target.prepare_for_lease(
            &context.publication.handle(),
            &lease,
            &offer.challenge,
            &context.edge_key,
            &context.host.identity,
        )?;
        let route = if matches!(
            lease.claims().definition.requested_ingress,
            ServiceIngress::Udp { .. }
        ) {
            if !carrier::datagram::supports_native(&context.connection) {
                return Err(SdkError::ServiceIo(std::io::ErrorKind::Unsupported.into()));
            }
            Some(context.datagrams.register(
                nestlink_node::service_plane::DatagramPacket::mapping_key(prepared.stream_id())?,
            )?)
        } else {
            None
        };
        write_message(stream.parts_mut().0, prepared.proof()).await?;
        let ready: ServiceStreamReady = read_message(stream.parts_mut().1).await?;
        if ready.stream_id != prepared.stream_id()
            || ready.lease_sha256 != prepared.proof().lease_sha256
        {
            return Err(SdkError::Trust);
        }
        Ok::<_, SdkError>((prepared, route))
    })
    .await
    .map_err(|_| SdkError::Timeout)??;
    let (prepared, route) = prepared;
    if let Some(route) = route {
        datagram::forward(prepared, stream, context, route).await?;
    } else if let Some(tls) = context.backend_tls {
        prepared
            .forward_https(
                stream,
                move |target| async move { tls.connect(target).await },
            )
            .await?;
    } else {
        prepared.forward_stream(stream).await?;
    }
    Ok(())
}
