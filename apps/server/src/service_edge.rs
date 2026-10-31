//! Real, pinned service-carrier endpoint and continuously driven TCP listeners.
//! It consumes only this runtime's verified service resource owner.
use nestlink_identity::{
    digest,
    nodes::NodeIdentity,
    service_plane::{publication::verify_attachment_proof, verify_tunnel_challenge},
};
use nestlink_node::{
    control::NodeControl,
    service_plane::{
        AcceptedServiceTcp, IngressNamespace, IngressOwnership, ServicePublicationHandle,
        ServiceTcpIngress, ServiceUdpIngress, ServiceWebIngress, ServiceWebVisitor,
    },
};
use nestlink_protocol::{
    api::ServiceIngress,
    service_plane::{publication::*, *},
    valid_id,
};
use nestlink_transport_quic::service::{self as carrier, BiStream, read_message, write_message};
use quinn::{Connection, Endpoint};
use std::{
    collections::HashMap,
    io,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{io::AsyncReadExt, sync::Semaphore, task::JoinSet};
pub mod caddy;
pub mod frontdoor;
mod group_health;
mod udp;
use carrier::datagram::DatagramRouter;
enum Ingress {
    Tcp(ServiceTcpIngress),
    Udp(ServiceUdpIngress),
    Web {
        ingress: ServiceWebIngress,
        route: caddy::Route,
    },
}

fn denied() -> io::Error {
    io::ErrorKind::PermissionDenied.into()
}
fn wall() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_millis()
        .try_into()
        .map_err(io::Error::other)
}
fn fault(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::other(error)
}
#[derive(Clone)]
struct Host {
    connection: Connection,
    key: [u8; 32],
    runtime: String,
    token: String,
    datagrams: DatagramRouter,
    ready: Arc<std::sync::atomic::AtomicBool>,
}
struct HostReady(Host);
impl Drop for HostReady {
    fn drop(&mut self) {
        self.0
            .ready
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }
}
struct Edge {
    node: Arc<NodeControl>,
    identity: Arc<NodeIdentity>,
    namespace: ServiceEdgeNamespaceView,
    ingress: IngressOwnership,
    bind_ip: IpAddr,
    hosts: Mutex<HashMap<String, Host>>,
    attachments: Mutex<HashMap<String, usize>>,
    openings: Arc<Semaphore>,
    caddy: Option<caddy::Controller>,
}
struct AttachmentDrainRegistration {
    edge: Arc<Edge>,
    publication_id: String,
}
impl AttachmentDrainRegistration {
    fn new(edge: Arc<Edge>, publication_id: String) -> io::Result<Self> {
        let mut attachments = edge.attachments.lock().map_err(|_| denied())?;
        let count = attachments.entry(publication_id.clone()).or_default();
        *count = count.checked_add(1).ok_or_else(denied)?;
        drop(attachments);
        Ok(Self {
            edge,
            publication_id,
        })
    }
}
impl Drop for AttachmentDrainRegistration {
    fn drop(&mut self) {
        if let Ok(mut attachments) = self.edge.attachments.lock()
            && let Some(count) = attachments.get_mut(&self.publication_id)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                attachments.remove(&self.publication_id);
            }
        }
    }
}
struct CloseConnection(Connection);
impl Drop for CloseConnection {
    fn drop(&mut self) {
        self.0.close(0u32.into(), b"service attachment ended");
    }
}
struct Registration {
    edge: Arc<Edge>,
    publication: String,
    token: String,
}
impl Drop for Registration {
    fn drop(&mut self) {
        if let Ok(mut hosts) = self.edge.hosts.lock()
            && hosts
                .get(&self.publication)
                .is_some_and(|h| h.token == self.token)
        {
            hosts.remove(&self.publication);
        }
    }
}
fn configured(edge: &Edge, publication: &ServicePublicationHandle) -> io::Result<()> {
    let lease = publication.lease().map_err(fault)?;
    let c = lease.claims();
    if c.edge_node_id() != edge.namespace.node_id
        || c.ingress_claim_revision != edge.namespace.revision
        || c.edge_service_address != edge.namespace.config.quic_address
        || c.edge_key_sha256 != digest(&edge.identity.public_key())
        || !edge
            .namespace
            .config
            .permits(&c.definition.requested_ingress)
        || matches!(
            c.definition.requested_ingress,
            ServiceIngress::Http { .. } | ServiceIngress::Https { .. }
        ) && edge.caddy.is_none()
    {
        return Err(denied());
    }
    edge.node.inspect_service_lease(&lease).map_err(fault)?;
    Ok(())
}
fn complete_ready_drains(edge: &Edge) -> io::Result<()> {
    let candidates = edge.node.service_drain_candidates().map_err(fault)?;
    for (publication_id, publication) in candidates {
        if edge
            .attachments
            .lock()
            .map_err(|_| denied())?
            .contains_key(&publication_id)
        {
            continue;
        }
        let Some(token) = publication.try_drain_token().map_err(fault)? else {
            continue;
        };
        edge.node
            .confirm_service_drain(&publication_id, token)
            .map_err(fault)?;
    }
    Ok(())
}
async fn stopped(publication: &ServicePublicationHandle, node: &NodeControl) {
    let mut node_stop = node.stopped();
    loop {
        if *node_stop.borrow()
            || publication
                .lease()
                .and_then(|lease| {
                    node.inspect_service_lease(&lease)
                        .map(|_| ())
                        .map_err(Into::into)
                })
                .is_err()
        {
            return;
        }
        tokio::select! { _=node_stop.changed()=>{},_=tokio::time::sleep(Duration::from_millis(25))=>{} }
    }
}
/// `namespace` is an operator-maintained copy of the administrator API's exact
/// namespace revision. A mismatch refuses publication rather than changing ports.
pub async fn serve(
    endpoint: Endpoint,
    node: Arc<NodeControl>,
    identity: Arc<NodeIdentity>,
    namespace: ServiceEdgeNamespaceView,
    bind_ip: IpAddr,
    shutdown: impl std::future::Future<Output = ()>,
) -> io::Result<()> {
    serve_with_caddy(endpoint, node, identity, namespace, bind_ip, None, shutdown).await
}
pub async fn serve_with_caddy(
    endpoint: Endpoint,
    node: Arc<NodeControl>,
    identity: Arc<NodeIdentity>,
    namespace: ServiceEdgeNamespaceView,
    bind_ip: IpAddr,
    caddy_config: Option<caddy::CaddyServiceConfig>,
    shutdown: impl std::future::Future<Output = ()>,
) -> io::Result<()> {
    serve_with_caddy_and_health(
        endpoint,
        node,
        identity,
        namespace,
        bind_ip,
        ServiceEdgeIngress { caddy: caddy_config, group_health_listen: None },
        shutdown,
    )
    .await
}
/// Operator-selected HTTP ingress and the readiness endpoint tied to its owner.
pub struct ServiceEdgeIngress {
    pub caddy: Option<caddy::CaddyServiceConfig>,
    pub group_health_listen: Option<std::net::SocketAddr>,
}
pub async fn serve_with_caddy_and_health(
    endpoint: Endpoint,
    node: Arc<NodeControl>,
    identity: Arc<NodeIdentity>,
    namespace: ServiceEdgeNamespaceView,
    bind_ip: IpAddr,
    ingress_config: ServiceEdgeIngress,
    shutdown: impl std::future::Future<Output = ()>,
) -> io::Result<()> {
    namespace.config.validate().map_err(fault)?;
    if !valid_id(&namespace.node_id) || namespace.revision == 0 {
        return Err(denied());
    }
    let ingress = IngressOwnership::new(
        IngressNamespace::new(
            namespace.node_id.clone(),
            namespace.config.service_suffix.clone(),
            namespace.config.management_hostname.clone(),
            namespace.config.public_ports.clone(),
        )
        .map_err(fault)?,
    );
    let driver = match ingress_config.caddy {
        Some(config) => Some(caddy::Controller::start(config, &namespace).await?),
        None => None,
    };
    let edge = Arc::new(Edge {
        node: node.clone(),
        identity,
        namespace,
        ingress,
        bind_ip,
        hosts: Mutex::new(HashMap::new()),
        attachments: Mutex::new(HashMap::new()),
        openings: Arc::new(Semaphore::new(SERVICE_MAX_OPENINGS)),
        caddy: driver.as_ref().map(caddy::Driver::controller),
    });
    let health = match ingress_config.group_health_listen {
        Some(address) => Some(group_health::Driver::start(address, edge.clone()).await?),
        None => None,
    };
    let connection_slots = Arc::new(Semaphore::new(SERVICE_MAX_OPENINGS));
    let mut connections = JoinSet::new();
    let mut node_stop = node.stopped();
    let mut drain_tick = tokio::time::interval(Duration::from_millis(100));
    drain_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tokio::pin!(shutdown);
    let caddy_failure = async {
        match &edge.caddy {
            Some(caddy) => caddy.failed().await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(caddy_failure);
    let health_failed = health.as_ref().map(group_health::Driver::failed);
    let health_failure = async move {
        match health_failed {
            Some(failed) => failed.await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(health_failure);
    let result = loop {
        tokio::select! {biased;
            _=&mut shutdown=>break Ok(()),
            _=&mut caddy_failure=>break Err(denied()),
            _=&mut health_failure=>break Err(denied()),
            _=node_stop.changed()=>{if *node_stop.borrow(){break Err(denied());}},
            Some(_)=connections.join_next()=>{},
            _=drain_tick.tick()=>{if let Err(error)=complete_ready_drains(&edge){break Err(error);}},
            incoming=endpoint.accept()=>{
                let Some(incoming)=incoming else{break Err(io::ErrorKind::ConnectionAborted.into());};
                let Ok(slot)=connection_slots.clone().try_acquire_owned()else{incoming.refuse();continue;};
                let copy=edge.clone();connections.spawn(async move{
                    let _slot=slot;
                    let connection=tokio::time::timeout(Duration::from_secs(2),incoming).await.map_err(fault)?.map_err(fault)?;
                    attach(copy,connection).await
                });
            },
        }
    };
    // Close service admission before the exact listener/flow owners begin
    // joining. Retired grant handles remain held by NodeControl for sealing.
    node.stop_service_publications().map_err(fault)?;
    endpoint.close(0u32.into(), b"service edge stopped");
    // Closing the endpoint wakes every attachment. Let each attachment close
    // its listener and join its flow tasks; aborting it here would drop its
    // nested JoinSet before the physical cleanup was acknowledged.
    while connections.join_next().await.is_some() {}
    endpoint.wait_idle().await;
    for (publication_id, publication) in node.service_drain_candidates().map_err(fault)? {
        if let Some(token) = publication.try_drain_token().map_err(fault)? {
            node.confirm_service_drain(&publication_id, token)
                .map_err(fault)?;
        }
    }
    // A bounded opportunity to deliver frozen report/seal bytes. If the
    // control plane is unavailable, the unresolved remainder stays held.
    let _ = node
        .wait_service_usage_settled(Duration::from_secs(5))
        .await
        .map_err(fault)?;
    if let Some(health) = health {
        health.shutdown().await?;
    }
    if let Some(driver) = driver {
        driver.shutdown().await?;
    }
    result
}
async fn attach(edge: Arc<Edge>, connection: Connection) -> io::Result<()> {
    let _closed = CloseConnection(connection.clone());
    if !carrier::negotiated_service(&connection) {
        return Err(denied());
    }
    let began = Instant::now();
    let deadline = began + Duration::from_secs(2);
    let (
        publication,
        host,
        _registration,
        _attachment,
        mut ingress,
        digest,
        mut sequence,
        mut send,
        mut recv,
    ) = tokio::time::timeout_at(deadline.into(), async {
        let (mut send, mut recv) = connection.accept_bi().await.map_err(fault)?;
        let intro: ServiceHostIntroduction = read_message(&mut recv).await?;
        if !valid_id(&intro.publication_id) || intro.generation == 0 {
            return Err(denied());
        }
        // Register before looking up the lease, so a concurrent retired-
        // grant scan cannot seal while this exact attachment is handshaking.
        let attachment =
            AttachmentDrainRegistration::new(edge.clone(), intro.publication_id.clone())?;
        // The HTTP grant can precede the next independent node resource
        // poll. Wait within the same bounded unauthenticated handshake;
        // only the actual retained resource owner can supply this handle.
        let publication = loop {
            if let Ok(publication) = edge.node.service_publication(&intro.publication_id) {
                break publication;
            }
            let mut node_stop = edge.node.stopped();
            if *node_stop.borrow() {
                return Err(denied());
            }
            tokio::select! {
                _=node_stop.changed()=>return Err(denied()),
                _=tokio::time::sleep(Duration::from_millis(25))=>{},
            }
        };
        configured(&edge, &publication)?;
        let lease = publication.lease().map_err(fault)?;
        if lease.claims().publication_generation != intro.generation
            || lease.claims().host_key_sha256 != digest(&intro.host_public_key)
        {
            return Err(denied());
        }
        let challenge = edge
            .identity
            .challenge_service_attachment(&lease, wall()?)
            .map_err(fault)?;
        write_message(
            &mut send,
            &ServiceAttachmentOffer {
                lease: lease.signed().clone(),
                challenge: challenge.clone(),
            },
        )
        .await?;
        let proof: ServiceAttachmentProof = tokio::select! {biased;
            _=stopped(&publication,&edge.node)=>return Err(denied()),
            proof=read_message(&mut recv)=>proof?,
        };
        verify_attachment_proof(
            &lease,
            &challenge,
            &proof,
            &intro.host_public_key,
            &edge.identity.public_key(),
            wall()?,
        )
        .map_err(fault)?;
        configured(&edge, &publication)?;
        // Bind after possession proof and before readiness. The attachment owns
        // this listener; cancellation releases the OS port and every flow.
        let reservation = edge
            .ingress
            .reserve(&publication, &edge.node)
            .map_err(fault)?;
        let ingress = match &lease.claims().definition.requested_ingress {
            ServiceIngress::Tcp { .. } => Ingress::Tcp(
                ServiceTcpIngress::bind(reservation, &edge.node, edge.bind_ip)
                    .await
                    .map_err(fault)?,
            ),
            ServiceIngress::Udp { .. } if carrier::datagram::supports_native(&connection) => {
                Ingress::Udp(
                    ServiceUdpIngress::bind(reservation, &edge.node, edge.bind_ip)
                        .await
                        .map_err(fault)?,
                )
            }
            ServiceIngress::Http { .. } | ServiceIngress::Https { .. } => {
                let ingress = ServiceWebIngress::bind(reservation, &edge.node)
                    .await
                    .map_err(fault)?;
                let route = edge.caddy.as_ref().ok_or_else(denied)?.register(
                    &ingress,
                    publication.clone(),
                    edge.node.clone(),
                    connection.clone(),
                )?;
                Ingress::Web { ingress, route }
            }
            _ => return Err(denied()),
        };
        let host = Host {
            connection: connection.clone(),
            key: intro.host_public_key,
            runtime: proof.host_runtime_id.clone(),
            token: uuid::Uuid::new_v4().to_string(),
            datagrams: DatagramRouter::new(),
            ready: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        {
            let mut hosts = edge.hosts.lock().map_err(|_| denied())?;
            if hosts.len() >= SERVICE_PUBLICATIONS_PER_NODE
                || hosts.contains_key(&intro.publication_id)
            {
                return Err(denied());
            }
            hosts.insert(intro.publication_id.clone(), host.clone());
        }
        let registration = Registration {
            edge: edge.clone(),
            publication: intro.publication_id,
            token: host.token.clone(),
        };
        Ok::<_, io::Error>((
            publication,
            host,
            registration,
            attachment,
            ingress,
            lease.digest(),
            lease.claims().lease_sequence,
            send,
            recv,
        ))
    })
    .await
    .map_err(fault)??;
    let publication_id = _registration.publication.clone();
    let prepare = async {
        if let Ingress::Web { route, .. } = &mut ingress {
            let mut tick = tokio::time::interval(Duration::from_millis(25));
            loop {
                tokio::select! {biased;
                    _=stopped(&publication,&edge.node)=>return Err(denied()),
                    _=connection.closed()=>return Err(denied()),
                    result=route.ready()=>{result?;break;},
                    _=tick.tick()=>{send_renewal(&edge,&publication,&mut sequence,&mut send).await?;},
                }
            }
        }
        let lease = publication.lease().map_err(fault)?;
        let c = lease.claims();
        let write_budget = if matches!(ingress, Ingress::Web { .. }) {
            Duration::from_millis(700)
        } else {
            deadline.saturating_duration_since(Instant::now())
        };
        tokio::time::timeout(
            write_budget,
            write_message(
                &mut send,
                &ServiceAttachmentReady {
                    publication_id: c.publication_id.clone(),
                    generation: c.publication_generation,
                    host_runtime_id: host.runtime.clone(),
                    lease_sha256: digest,
                },
            ),
        )
        .await
        .map_err(fault)??;
        Ok::<_, io::Error>(())
    };
    if let Err(error) = prepare.await {
        close_ingress(ingress).await;
        return Err(error);
    }
    host.ready.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ready = HostReady(host.clone());
    let renewals = async {
        let mut tick = tokio::time::interval(Duration::from_millis(25));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            configured(&edge, &publication)?;
            send_renewal(&edge, &publication, &mut sequence, &mut send).await?;
        }
    };
    let unexpected = async {
        let mut byte = [0];
        let _ = AsyncReadExt::read(&mut recv, &mut byte).await;
        Err::<(), io::Error>(denied())
    };
    let router = host.datagrams.clone();
    let datagram_connection = connection.clone();
    let mut datagrams = tokio::spawn(async move { router.drive(&datagram_connection, true).await });
    let listening = async {
        match ingress {
            Ingress::Tcp(ingress) => {
                listener(edge.clone(), host.clone(), publication.clone(), ingress).await
            }
            Ingress::Udp(ingress) => {
                udp::listener(edge.clone(), host.clone(), publication.clone(), ingress).await
            }
            Ingress::Web { ingress, route } => {
                web_listener(
                    edge.clone(),
                    host.clone(),
                    publication.clone(),
                    ingress,
                    route,
                )
                .await
            }
        }
    };
    tokio::pin!(listening);
    let (result, listener_joined) = tokio::select! {biased;
        _=stopped(&publication,&edge.node)=>(Err(denied()),false),
        _=connection.closed()=>(Err(denied()),false),
        _=connection.accept_bi()=>(Err(denied()),false),
        result=&mut listening=>(result,true),
        result=unexpected=>(result,false),
        result=renewals=>(result,false),
    };
    connection.close(0u32.into(), b"service attachment cleanup");
    if !listener_joined {
        let _ = listening.await;
    }
    datagrams.abort();
    let _ = (&mut datagrams).await;
    host.datagrams.close();
    if publication.is_stopped().map_err(fault)? {
        // All attachment flow workers and the datagram driver are joined. The
        // connection is publication-scoped, so its close completes the local
        // QUIC drain without waiting for unrelated publications on the endpoint.
        connection.closed().await;
        let token = publication.wait_drained().await.map_err(fault)?;
        edge.node
            .confirm_service_drain(&publication_id, token)
            .map_err(fault)?;
    }
    result
}
async fn close_ingress(ingress: Ingress) {
    match ingress {
        Ingress::Tcp(mut ingress) => ingress.close(),
        Ingress::Udp(ingress) => drop(ingress),
        Ingress::Web {
            mut ingress,
            mut route,
        } => {
            ingress.close();
            route.close().await;
        }
    }
}
async fn send_renewal(
    edge: &Edge,
    publication: &ServicePublicationHandle,
    sequence: &mut u64,
    send: &mut quinn::SendStream,
) -> io::Result<()> {
    configured(edge, publication)?;
    let lease = publication.lease().map_err(fault)?;
    if lease.claims().lease_sequence < *sequence {
        return Err(denied());
    }
    if lease.claims().lease_sequence > *sequence {
        let renewal = edge
            .node
            .service_publication_renewal(&lease.claims().publication_id)
            .map_err(fault)?;
        let sent = decode_service_message::<ServiceLeaseClaims>(
            &renewal.lease.claims,
            SERVICE_MESSAGE_BYTES,
        )
        .map_err(fault)?
        .lease_sequence;
        tokio::time::timeout(Duration::from_millis(700), write_message(send, &renewal))
            .await
            .map_err(fault)??;
        *sequence = sent;
    }
    Ok(())
}
async fn web_listener(
    edge: Arc<Edge>,
    host: Host,
    publication: ServicePublicationHandle,
    mut ingress: ServiceWebIngress,
    mut route: caddy::Route,
) -> io::Result<()> {
    let mut tasks = JoinSet::new();
    let result = loop {
        tokio::select! {biased;
            _=stopped(&publication,&edge.node)=>break Err(denied()),
            _=host.connection.closed()=>break Err(denied()),
            _=route.ended()=>break Err(denied()),
            Some(_)=tasks.join_next()=>{},
            visitor=ingress.accept(&edge.node)=>{
                let visitor=match visitor{Ok(visitor)=>visitor,Err(error)=>break Err(fault(error))};
                let Ok(slot)=edge.openings.clone().try_acquire_owned()else{drop(visitor);continue;};
                let edge=edge.clone();let host=host.clone();tasks.spawn(async move{let _slot=slot;forward_web(edge,host,visitor).await});
            },
        }
    };
    ingress.close();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    route.close().await;
    result
}
async fn forward_web(edge: Arc<Edge>, host: Host, visitor: ServiceWebVisitor) -> io::Result<()> {
    let pending = visitor
        .authenticate(&edge.node, &edge.identity)
        .await
        .map_err(fault)?;
    let deadline = Instant::now() + Duration::from_secs(2);
    let challenge = verify_tunnel_challenge(
        pending.challenge(),
        pending.lease(),
        &edge.identity.public_key(),
    )
    .map_err(fault)?;
    let negotiate = async {
        let (send, recv) = host.connection.open_bi().await.map_err(fault)?;
        let mut stream = BiStream::new(send, recv);
        write_message(
            stream.parts_mut().0,
            &ServiceStreamOffer {
                lease: pending.lease().signed().clone(),
                challenge: pending.challenge().clone(),
            },
        )
        .await?;
        let proof: ServiceTunnelProof = read_message(stream.parts_mut().1).await?;
        Ok::<_, io::Error>((stream, proof))
    };
    let (mut stream, proof) = tokio::select! {biased;
        _=pending.wait_stopped()=>return Err(denied()),
        result=tokio::time::timeout_at(deadline.into(),negotiate)=>result.map_err(fault)??,
    };
    if proof.host_runtime_id != host.runtime {
        return Err(denied());
    }
    let authorized = pending.accept_proof(&host.key, &proof).map_err(fault)?;
    tokio::time::timeout_at(
        deadline.into(),
        write_message(
            stream.parts_mut().0,
            &ServiceStreamReady {
                stream_id: challenge.stream_id,
                lease_sha256: proof.lease_sha256,
            },
        ),
    )
    .await
    .map_err(fault)??;
    tokio::select! {biased;_=host.connection.closed()=>Err(denied()),result=authorized.forward(stream)=>result.map_err(fault)}
}
async fn listener(
    edge: Arc<Edge>,
    host: Host,
    publication: ServicePublicationHandle,
    mut ingress: ServiceTcpIngress,
) -> io::Result<()> {
    configured(&edge, &publication)?;
    let mut tasks = JoinSet::new();
    let result = loop {
        tokio::select! {biased;
            _=stopped(&publication,&edge.node)=>break Err(denied()),
            _=host.connection.closed()=>break Err(denied()),
            Some(_)=tasks.join_next()=>{},
            accepted=ingress.accept(&edge.node)=>{
                let accepted=match accepted {Ok(visitor)=>visitor,Err(error)=>break Err(fault(error))};
                let Ok(slot)=edge.openings.clone().try_acquire_owned()else{drop(accepted);continue;};
                let copy=edge.clone();let host=host.clone();tasks.spawn(async move{let _slot=slot;forward(copy,host,accepted).await});
            },
        }
    };
    ingress.close();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    result
}
async fn forward(edge: Arc<Edge>, host: Host, visitor: AcceptedServiceTcp) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let pending = visitor.challenge(&edge.identity).map_err(fault)?;
    let challenge = verify_tunnel_challenge(
        pending.challenge(),
        pending.lease(),
        &edge.identity.public_key(),
    )
    .map_err(fault)?;
    let offer = ServiceStreamOffer {
        lease: pending.lease().signed().clone(),
        challenge: pending.challenge().clone(),
    };
    let negotiate = async {
        let (send, recv) = host.connection.open_bi().await.map_err(fault)?;
        let mut stream = BiStream::new(send, recv);
        let (send, recv) = stream.parts_mut();
        write_message(send, &offer).await?;
        let proof: ServiceTunnelProof = read_message(recv).await?;
        Ok::<_, io::Error>((stream, proof))
    };
    let (mut stream, proof) = tokio::select! {biased;
        _=pending.wait_stopped()=>return Err(denied()),
        result=tokio::time::timeout_at(deadline.into(),negotiate)=>result.map_err(fault)??,
    };
    if proof.host_runtime_id != host.runtime {
        return Err(denied());
    }
    let authorized = pending.accept_proof(&host.key, &proof).map_err(fault)?;
    let ready = ServiceStreamReady {
        stream_id: challenge.stream_id,
        lease_sha256: proof.lease_sha256,
    };
    tokio::time::timeout_at(deadline.into(), write_message(stream.parts_mut().0, &ready))
        .await
        .map_err(fault)??;
    tokio::select! {biased;
        _=host.connection.closed()=>Err(denied()),
        result=authorized.forward(stream)=>result.map_err(fault),
    }
}
