//! Linux ordinary-user raw TCP/UDP entry behind an administrator-installed
//! nftables UID/endpoint fence. All remote authority remains in the original
//! private-service SDK; no packet chooses an Internet or local backend target.
use super::*;
use nestlink_node::service_plane::DatagramPacket;
use nestlink_platform_security::local_port_gate::{GatePlan, RootGateReceipt, Transport};
use std::collections::BTreeMap;
use tokio::{net::UdpSocket, sync::mpsc};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawProxyStopReport {
    pub accepted_connections: u64,
    pub completed_connections: u64,
    pub rejected_connections: u64,
    pub failed_connections: u64,
    pub cleanup_failures: u64,
    pub forwarded_datagrams: u64,
    pub discarded_datagrams: u64,
    pub socket_closed: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawProxyWait {
    CleanupPending,
    Stopped(RawProxyStopReport),
    CleanupFailed(RawProxyStopReport),
}
pub struct LocalRawServiceProxy {
    address: SocketAddr,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<RawProxyStopReport>>,
    report: Option<RawProxyStopReport>,
    runtime: tokio::runtime::Handle,
}
impl LocalRawServiceProxy {
    pub fn address(&self) -> SocketAddr {
        self.address
    }
    pub fn is_finished(&self) -> bool {
        self.report.is_some() || self.task.as_ref().is_none_or(JoinHandle::is_finished)
    }
    pub fn request_shutdown(&self) {
        self.stop.send_replace(true);
    }
    pub async fn wait_stopped(&mut self, budget: Duration) -> RawProxyWait {
        self.request_shutdown();
        if let Some(task) = self.task.as_mut() {
            let result = match tokio::time::timeout(budget, &mut *task).await {
                Ok(result) => result,
                Err(_) => return RawProxyWait::CleanupPending,
            };
            self.task.take();
            self.report = Some(result.unwrap_or_else(|_| RawProxyStopReport {
                cleanup_failures: 1,
                ..RawProxyStopReport::default()
            }));
        }
        let report = self.report.clone().unwrap_or_else(|| RawProxyStopReport {
            cleanup_failures: 1,
            ..RawProxyStopReport::default()
        });
        if report.cleanup_failures == 0 && report.socket_closed {
            RawProxyWait::Stopped(report)
        } else {
            RawProxyWait::CleanupFailed(report)
        }
    }
}
impl Drop for LocalRawServiceProxy {
    fn drop(&mut self) {
        self.request_shutdown();
        if let Some(task) = self.task.take() {
            self.runtime.spawn(async move {
                let _ = task.await;
            });
        }
    }
}
enum Listener {
    Tcp(TcpListener),
    Udp(Arc<UdpSocket>),
}
impl Sdk {
    /// The original live daemon process must first publish its private plan and
    /// obtain this administrator's root-owned receipt. A loopback address, a
    /// claimed PID, or a service grant alone can never enable a raw listener.
    pub async fn start_private_service_raw(
        self: &Arc<Self>,
        consumer: Arc<DeviceIdentity>,
        choice: LocalProxyServiceChoice,
        plan: GatePlan,
        receipt_path: &Path,
    ) -> Result<LocalRawServiceProxy, LocalProxyError> {
        if !valid_id(&consumer.device_id) {
            return Err(LocalProxyError::Invalid);
        }
        let transport = if matches!(
            choice.entry.service.definition.requested_ingress,
            ServiceIngress::Udp { .. }
        ) {
            Transport::Udp
        } else {
            Transport::Tcp
        };
        if plan.transport != transport {
            return Err(LocalProxyError::Invalid);
        }
        self.principal().ok_or(SdkError::SignIn)?;
        let receipt = RootGateReceipt::read_for_current_process(receipt_path, &plan)?;
        let remaining = plan
            .expires_at_ms
            .checked_sub(nestlink_platform_security::local_port_gate::wall_ms()?)
            .ok_or(LocalProxyError::Invalid)?;
        let deadline = Instant::now() + choice.lifetime.min(Duration::from_millis(remaining));
        let owner = owners()
            .clone()
            .try_acquire_owned()
            .map_err(|_| LocalProxyError::Busy)?;
        let listener = match transport {
            Transport::Tcp => Listener::Tcp(TcpListener::bind(plan.endpoint).await?),
            Transport::Udp => Listener::Udp(Arc::new(UdpSocket::bind(plan.endpoint).await?)),
        };
        receipt.check_current(&plan)?;
        let address = plan.endpoint;
        let (stop, stopped) = watch::channel(false);
        let task = tokio::spawn(run_owner(
            self.clone(),
            consumer,
            Arc::new(choice),
            listener,
            plan,
            receipt,
            stopped,
            deadline,
            owner,
        ));
        Ok(LocalRawServiceProxy {
            address,
            stop,
            task: Some(task),
            report: None,
            runtime: tokio::runtime::Handle::current(),
        })
    }
}
fn record(
    report: &mut RawProxyStopReport,
    outcome: Option<Result<(SocketAddr, FlowOutcome), tokio::task::JoinError>>,
    peers: &mut BTreeMap<SocketAddr, mpsc::Sender<Vec<u8>>>,
) {
    report.completed_connections += 1;
    match outcome {
        Some(Ok((peer, outcome))) => {
            peers.remove(&peer);
            report.rejected_connections += u64::from(outcome.rejected);
            report.failed_connections += u64::from(outcome.failed);
            report.cleanup_failures += u64::from(outcome.cleanup_failed);
            report.forwarded_datagrams += outcome.forwarded_datagrams;
            report.discarded_datagrams += outcome.discarded_datagrams;
        }
        _ => report.cleanup_failures += 1,
    }
}
#[allow(clippy::too_many_arguments)]
async fn run_owner(
    sdk: Arc<Sdk>,
    consumer: Arc<DeviceIdentity>,
    choice: Arc<LocalProxyServiceChoice>,
    listener: Listener,
    plan: GatePlan,
    receipt: RootGateReceipt,
    mut stop: watch::Receiver<bool>,
    deadline: Instant,
    _owner: tokio::sync::OwnedSemaphorePermit,
) -> RawProxyStopReport {
    let mut report = RawProxyStopReport::default();
    let mut workers = JoinSet::new();
    let (worker_stop, stopped) = watch::channel(false);
    let mut peers = BTreeMap::new();
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    let mut buffer = vec![0u8; 65536];
    let mut events = 0u64;
    loop {
        enum Incoming {
            Tcp(io::Result<(TcpStream, SocketAddr)>),
            Udp(io::Result<(usize, SocketAddr)>),
        }
        let incoming = async {
            match &listener {
                Listener::Tcp(listener) => Incoming::Tcp(listener.accept().await),
                Listener::Udp(socket) => Incoming::Udp(socket.recv_from(&mut buffer).await),
            }
        };
        let event = tokio::select! {biased;
            _=stopping(&mut stop)=>break,
            _=tokio::time::sleep_until(deadline)=>break,
            _=tick.tick()=>{if receipt.check_current(&plan).is_err() {report.failed_connections+=1;break;} continue;},
            outcome=workers.join_next(),if !workers.is_empty()=>{record(&mut report,outcome,&mut peers);continue;},
            event=incoming=>event,
        };
        match event {
            Incoming::Tcp(Ok((socket, peer))) => {
                if !peer.ip().is_loopback() || receipt.check_current(&plan).is_err() {
                    report.rejected_connections += 1;
                    drop(socket);
                    continue;
                }
                report.accepted_connections += 1;
                if workers.len() >= OWNER_FLOWS {
                    report.rejected_connections += 1;
                    drop(socket);
                    continue;
                }
                let Ok(permit) = flows().clone().try_acquire_owned() else {
                    report.rejected_connections += 1;
                    drop(socket);
                    continue;
                };
                let (sdk, consumer, choice, stopped) = (
                    sdk.clone(),
                    consumer.clone(),
                    choice.clone(),
                    stopped.clone(),
                );
                workers.spawn(async move {
                    let _permit = permit;
                    (
                        peer,
                        super::native_stream::forward(
                            sdk, consumer, choice, socket, stopped, deadline,
                        )
                        .await,
                    )
                });
            }
            Incoming::Udp(Ok((size, peer))) => {
                events = events.saturating_add(1);
                if events > 65536 {
                    report.discarded_datagrams += 1;
                    break;
                }
                if !peer.ip().is_loopback() || size > DatagramPacket::MAX_PAYLOAD {
                    report.discarded_datagrams += 1;
                    continue;
                }
                if let Some(sender) = peers.get(&peer) {
                    if sender.try_send(buffer[..size].to_vec()).is_err() {
                        report.discarded_datagrams += 1;
                    }
                    continue;
                }
                if receipt.check_current(&plan).is_err() {
                    report.failed_connections += 1;
                    break;
                }
                if workers.len() >= OWNER_FLOWS {
                    report.rejected_connections += 1;
                    continue;
                }
                let Ok(permit) = flows().clone().try_acquire_owned() else {
                    report.rejected_connections += 1;
                    continue;
                };
                let Listener::Udp(socket) = &listener else {
                    report.cleanup_failures += 1;
                    break;
                };
                let (sender, receiver) = mpsc::channel(16);
                if sender.try_send(buffer[..size].to_vec()).is_err() {
                    report.discarded_datagrams += 1;
                    continue;
                }
                peers.insert(peer, sender);
                report.accepted_connections += 1;
                let (sdk, consumer, choice, stopped, socket) = (
                    sdk.clone(),
                    consumer.clone(),
                    choice.clone(),
                    stopped.clone(),
                    socket.clone(),
                );
                workers.spawn(async move {
                    let _permit = permit;
                    (
                        peer,
                        forward_udp(
                            sdk, consumer, choice, socket, peer, receiver, stopped, deadline,
                        )
                        .await,
                    )
                });
            }
            Incoming::Tcp(Err(_)) | Incoming::Udp(Err(_)) => {
                report.cleanup_failures += 1;
                break;
            }
        }
    }
    worker_stop.send_replace(true);
    peers.clear();
    // Every cloned UDP handle and remote carrier belongs to these original
    // workers. Do not report socket close before their physical join receipts.
    while !workers.is_empty() {
        record(&mut report, workers.join_next().await, &mut peers);
    }
    drop(listener);
    report.socket_closed = true;
    report
}
#[allow(clippy::too_many_arguments)]
async fn forward_udp(
    sdk: Arc<Sdk>,
    consumer: Arc<DeviceIdentity>,
    choice: Arc<LocalProxyServiceChoice>,
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    mut packets: mpsc::Receiver<Vec<u8>>,
    mut stop: watch::Receiver<bool>,
    owner_deadline: Instant,
) -> FlowOutcome {
    let setup_deadline = (Instant::now() + SETUP_BUDGET).min(owner_deadline);
    let request = match choice.access_request(&consumer) {
        Ok(request) => request,
        Err(_) => {
            return FlowOutcome {
                rejected: true,
                ..FlowOutcome::default()
            };
        }
    };
    let lease = tokio::select! {biased;
        _=stopping(&mut stop)=>return FlowOutcome::default(),
        result=tokio::time::timeout_at(setup_deadline,sdk.request_private_service(&choice.entry.service.id,request))=>match result {
            Ok(Ok(lease)) if choice.checks_lease(&lease)=>lease,
            _=>return FlowOutcome {rejected:true,..FlowOutcome::default()},
        },
    };
    let connecting =
        sdk.connect_private_service_with_relay_policy(&consumer, lease, &choice.relay_policy);
    tokio::pin!(connecting);
    let result = tokio::select! {biased;
        _=stopping(&mut stop)=>None,
        _=tokio::time::sleep_until(setup_deadline)=>None,
        result=&mut connecting=>Some(result),
    };
    let mut connection = match result {
        Some(Ok(connection)) => connection,
        Some(Err(_)) => {
            return FlowOutcome {
                failed: true,
                cleanup_failed: true,
                ..FlowOutcome::default()
            };
        }
        None => {
            return FlowOutcome {
                cleanup_failed: match connecting.await {
                    Ok(mut connection) => connection.close().await.is_err(),
                    Err(_) => true,
                },
                ..FlowOutcome::default()
            };
        }
    };
    let mut outcome = FlowOutcome::default();
    let lease = connection.lease().clone();
    let expired = authority_expired(&lease);
    tokio::pin!(expired);
    let idle = Duration::from_secs(u64::from(
        choice.entry.service.definition.limits.idle_timeout_seconds,
    ));
    let mut idle_deadline = Instant::now() + idle;
    let mut bytes = 0u64;
    let mut events = 0u64;
    loop {
        enum Event {
            Local(Option<Vec<u8>>),
            Remote(Result<Vec<u8>, SdkError>),
        }
        let data = async {
            tokio::select! {packet=packets.recv()=>Event::Local(packet),packet=connection.receive_datagram()=>Event::Remote(packet)}
        };
        let event = tokio::select! {biased;
            _=stopping(&mut stop)=>break,
            _=tokio::time::sleep_until(owner_deadline.min(idle_deadline))=>break,
            _=&mut expired=>break,
            event=data=>event,
        };
        events = events.saturating_add(1);
        if events > 8192 {
            outcome.discarded_datagrams += 1;
            break;
        }
        let (packet, local) = match event {
            Event::Local(Some(packet)) => (packet, true),
            Event::Remote(Ok(packet)) => (packet, false),
            Event::Local(None) => break,
            Event::Remote(Err(_)) => {
                outcome.failed = true;
                break;
            }
        };
        if packet.len() > DatagramPacket::MAX_PAYLOAD {
            outcome.discarded_datagrams += 1;
            continue;
        }
        let Some(next) = bytes
            .checked_add(packet.len() as u64)
            .filter(|next| *next <= choice.maximum_bytes)
        else {
            outcome.discarded_datagrams += 1;
            break;
        };
        bytes = next;
        if lease.check_time(wall_ms().unwrap_or(0)).is_err() {
            break;
        }
        if local {
            if connection.send_datagram(&packet).is_err() {
                outcome.failed = true;
                break;
            }
        } else {
            let result = tokio::select! {biased;
                _=stopping(&mut stop)=>break,
                _=&mut expired=>break,
                result=tokio::time::timeout_at((Instant::now()+Duration::from_millis(250)).min(owner_deadline).min(idle_deadline),socket.send_to(&packet,peer))=>result,
            };
            if !matches!(result,Ok(Ok(size)) if size==packet.len()) {
                outcome.failed = true;
                break;
            }
        }
        outcome.forwarded_datagrams += 1;
        idle_deadline = Instant::now() + idle;
    }
    outcome.cleanup_failed = connection.close().await.is_err();
    outcome
}
