//! Real, current-authority neighbor observations on the original node socket.
//! A probe never reserves a relay Pair or carries business/datagram traffic.
use super::*;
use nestlink_identity::{digest, nodes::NodeIdentity};
use nestlink_node::control::TopologyReporter;
use nestlink_protocol::{
    api::{
        NetworkNodeTopologyAuthority, NetworkNodeTopologyNeighbor, NetworkTopologyProbe,
        NodeEndpointsView,
    },
    network::PeerId,
    network_topology::{BootIncarnation, MAX_NEIGHBORS, TopologyNeighbor},
};
use nestlink_transport_quic::routed::{
    authenticated_peer_fingerprint, topology_node_client_config,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
};
use tokio::{sync::OwnedSemaphorePermit, time::Instant as Deadline};

const MAX_SPACES: usize = 64;
const MAX_CONNECTIONS: usize = 16;
const MAX_ADDRESSES: usize = 32;
const PERIOD: Duration = Duration::from_millis(500);
const PROBE_BUDGET: Duration = Duration::from_millis(700);
const FRESH: Duration = Duration::from_millis(700);

#[derive(Clone, PartialEq, Eq)]
struct PeerKey {
    public_key: [u8; 32],
    incarnation: BootIncarnation,
    node: NodeEndpointsView,
}
impl From<&NetworkNodeTopologyNeighbor> for PeerKey {
    fn from(neighbor: &NetworkNodeTopologyNeighbor) -> Self {
        Self {
            public_key: neighbor.public_key,
            incarnation: neighbor.incarnation.clone(),
            node: neighbor.node.clone(),
        }
    }
}
#[derive(Clone)]
struct Work {
    authority: NetworkNodeTopologyAuthority,
    neighbor: NetworkNodeTopologyNeighbor,
    space: String,
}
#[derive(Clone)]
struct Group {
    key: PeerKey,
    work: Vec<Work>,
}
struct Session {
    key: PeerKey,
    work: Vec<Work>,
    connection: quinn::Connection,
    write: quinn::SendStream,
    read: quinn::RecvStream,
    _slot: OwnedSemaphorePermit,
}
struct Opening(Option<quinn::Connection>);
impl Drop for Opening {
    fn drop(&mut self) {
        if let Some(connection) = &self.0 {
            connection.close(0u32.into(), b"topology setup stopped");
        }
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.connection
            .close(0u32.into(), b"topology observation stopped");
    }
}
struct Observation {
    work: Work,
    completed: Deadline,
}
struct Outcome {
    node: String,
    session: Option<Session>,
    observations: Vec<Observation>,
    next_at: Deadline,
    failures: u8,
}

fn same_neighbor(left: &NetworkNodeTopologyNeighbor, right: &NetworkNodeTopologyNeighbor) -> bool {
    left.public_key == right.public_key
        && left.publisher_digest == right.publisher_digest
        && left.incarnation == right.incarnation
        && left.node == right.node
}
fn same_authority(
    left: &NetworkNodeTopologyAuthority,
    right: &NetworkNodeTopologyAuthority,
) -> bool {
    // A new accepted node lease can advance its observation expiry. All scope,
    // key, boot, publisher and endpoint bindings must remain exactly the same;
    // the getter independently enforces the current original monotonic bounds.
    left.authority_key == right.authority_key
        && left.publisher == right.publisher
        && left.publisher_digest == right.publisher_digest
        && left.route_exports == right.route_exports
        && left.local == right.local
        && left.neighbors.len() == right.neighbors.len()
        && left
            .neighbors
            .iter()
            .zip(&right.neighbors)
            .all(|(left, right)| same_neighbor(left, right))
}
fn same_work(left: &[Work], right: &[Work]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| {
            left.space == right.space
                && same_authority(&left.authority, &right.authority)
                && same_neighbor(&left.neighbor, &right.neighbor)
        })
}
fn current(control: &NodeControl, work: &Work) -> bool {
    control
        .network_topology_authority(&work.space)
        .is_ok_and(|authority| same_authority(&authority, &work.authority))
}
async fn work_stopped(control: &NodeControl, work: &[Work]) {
    loop {
        if work.iter().any(|work| !current(control, work)) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}
async fn peer_stopped(control: &NodeControl, peer: &[u8; 32]) {
    loop {
        if !control
            .network_topology_authorities()
            .is_ok_and(|authorities| {
                authorities.iter().any(|authority| {
                    authority
                        .neighbors
                        .iter()
                        .any(|neighbor| digest(&neighbor.public_key) == *peer)
                })
            })
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}
fn space(authority: &NetworkNodeTopologyAuthority) -> io::Result<String> {
    // The getter has already authenticated these canonical bytes against the
    // signed resource and retained the original monotonic validity boundary.
    Ok(
        nestlink_protocol::network_topology::TopologyPublisherClaims::decode_canonical(
            &authority.publisher.claims,
        )
        .map_err(io::Error::other)?
        .scope
        .space_id,
    )
}
fn groups(authorities: &[NetworkNodeTopologyAuthority]) -> io::Result<BTreeMap<String, Group>> {
    if authorities.len() > MAX_SPACES {
        return Err(failed());
    }
    let mut groups = BTreeMap::<String, Group>::new();
    for authority in authorities {
        if authority.neighbors.len() > MAX_NEIGHBORS {
            return Err(failed());
        }
        let space = space(authority)?;
        for neighbor in &authority.neighbors {
            let key = PeerKey::from(neighbor);
            let group = groups
                .entry(neighbor.node.node_id.clone())
                .or_insert_with(|| Group {
                    key: key.clone(),
                    work: Vec::new(),
                });
            if group.key != key || group.work.len() >= MAX_SPACES {
                return Err(failed());
            }
            group.work.push(Work {
                authority: authority.clone(),
                neighbor: neighbor.clone(),
                space: space.clone(),
            });
        }
    }
    Ok(groups)
}

/// One owner, at most sixteen reused physical-neighbor connections and at most
/// two report requests per space. Spaces sharing a neighbor share its probe stream;
/// they do not create one permanent task or socket for every space/edge pair.
pub(super) async fn run(
    endpoint: quinn::Endpoint,
    control: Arc<NodeControl>,
    selector: Arc<RelaySelector>,
    identity: Arc<NodeIdentity>,
    reporter: Arc<TopologyReporter>,
) -> io::Result<()> {
    let mut tick = tokio::time::interval(PERIOD);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut stopped = control.stopped();
    let mut probes = JoinSet::new();
    let mut reports = JoinSet::new();
    let mut in_flight = BTreeSet::<String>::new();
    let mut reporting = BTreeMap::<String, usize>::new();
    let mut active = BTreeSet::<String>::new();
    let mut observations = BTreeMap::<(String, String), Observation>::new();
    let mut current_groups = BTreeMap::<String, Group>::new();
    let result = async { loop {
        if *stopped.borrow() { return Ok(()); }
        tokio::select! { biased;
            _ = stopped.changed() => return Ok(()),
            result = probes.join_next(), if !probes.is_empty() => {
                let outcome: Outcome = result.ok_or_else(failed)?.map_err(io::Error::other)?;
                in_flight.remove(&outcome.node);
                observations.retain(|(_, node), _| node != &outcome.node);
                for observation in outcome.observations {
                    if current(&control, &observation.work) {
                        observations.insert((observation.work.space.clone(), outcome.node.clone()), observation);
                    }
                }
                if active.contains(&outcome.node)
                    && let Some(group) = current_groups.get(&outcome.node).cloned()
                    && group.work.iter().all(|work| current(&control, work))
                {
                    // Re-arm from the original measurement schedule immediately.
                    // A healthy 600ms probe must not wait for a later 500ms tick
                    // and manufacture a down edge under the unchanged 700ms TTL.
                    in_flight.insert(outcome.node.clone());
                    let endpoint = endpoint.clone(); let control = control.clone(); let selector = selector.clone(); let identity = identity.clone();
                    probes.spawn(async move { probe(outcome.node, group, outcome.session, endpoint, control, selector, identity, outcome.next_at, outcome.failures).await });
                }
            },
            result = reports.join_next(), if !reports.is_empty() => {
                let reported: String = result.ok_or_else(failed)?.map_err(io::Error::other)?;
                if let Some(count) = reporting.get_mut(&reported) { *count -= 1; }
                reporting.retain(|_, count| *count > 0);
            },
            _ = tick.tick() => {
                let authorities = control.network_topology_authorities().unwrap_or_default();
                current_groups = groups(&authorities)?;
                observations.retain(|_, observation| observation.completed.elapsed() < FRESH && current(&control, &observation.work));
                // Keep a stable admitted working set. Additional delegated
                // neighbors are reported down until a slot is free; rotating
                // the entire graph would repeatedly consume the shared IP rate.
                active.retain(|node| current_groups.contains_key(node));
                for node in current_groups.keys() {
                    if active.len() >= MAX_CONNECTIONS { break; }
                    active.insert(node.clone());
                }
                for node in active.clone() {
                    if in_flight.contains(&node) { continue; }
                    if in_flight.len() >= MAX_CONNECTIONS { break; }
                    let Some(group) = current_groups.get(&node).cloned() else { continue; };
                    in_flight.insert(node.clone());
                    let endpoint = endpoint.clone(); let control = control.clone(); let selector = selector.clone(); let identity = identity.clone();
                    probes.spawn(async move { probe(node, group, None, endpoint, control, selector, identity, Deadline::now(), 0).await });
                }
                for authority in authorities {
                    let space = space(&authority)?;
                    if reporting.get(&space).copied().unwrap_or_default() >= 2 { continue; }
                    let local = PeerId::from_public_key(&identity.public_key());
                    let neighbors = authority.neighbors.iter().map(|neighbor| TopologyNeighbor {
                        local, remote: PeerId::from_public_key(&neighbor.public_key),
                        local_endpoint_revision: authority.local.revision,
                        remote_endpoint_revision: neighbor.node.revision,
                        up: observations.get(&(space.clone(), neighbor.node.node_id.clone())).is_some_and(|observation| {
                            same_authority(&observation.work.authority, &authority) && same_neighbor(&observation.work.neighbor, neighbor) && observation.completed.elapsed() < FRESH
                        }),
                    }).collect();
                    // The bounded 700ms HTTP response may overlap the next
                    // 500ms send. Serializing responses would create a 1s gap
                    // and retire a healthy edge under the original 1s report TTL.
                    *reporting.entry(space.clone()).or_default() += 1;
                    let reporter = reporter.clone(); let control = control.clone();
                    reports.spawn(async move {
                        if let Err(error) = reporter.publish_authority(&control, &authority, neighbors).await {
                            tracing::debug!(space = %space, error = %error, "topology observation report failed");
                        }
                        space
                    });
                }
            },
        }
    }}.await;
    drop(observations);
    probes.abort_all();
    reports.abort_all();
    let deadline = Deadline::now() + Duration::from_secs(5);
    let mut cleanup_failed = false;
    while let Some(joined) = tokio::time::timeout_at(deadline, probes.join_next())
        .await
        .map_err(io::Error::other)?
    {
        if joined.is_err_and(|error| !error.is_cancelled()) {
            cleanup_failed = true;
        }
    }
    while let Some(joined) = tokio::time::timeout_at(deadline, reports.join_next())
        .await
        .map_err(io::Error::other)?
    {
        if joined.is_err_and(|error| !error.is_cancelled()) {
            cleanup_failed = true;
        }
    }
    if cleanup_failed {
        Err(failed())
    } else {
        result
    }
}

async fn address(endpoint: &quinn::Endpoint, node: &NodeEndpointsView) -> io::Result<SocketAddr> {
    node.endpoints.validate().map_err(io::Error::other)?;
    let uri = url::Url::parse(node.endpoints.quic_uri.as_deref().ok_or_else(failed)?)
        .map_err(io::Error::other)?;
    let port = uri.port().ok_or_else(failed)?;
    let addresses = match uri.host().ok_or_else(failed)? {
        url::Host::Ipv4(ip) => vec![SocketAddr::new(IpAddr::V4(ip), port)],
        url::Host::Ipv6(ip) => vec![SocketAddr::new(IpAddr::V6(ip), port)],
        url::Host::Domain(host) => tokio::net::lookup_host((host, port))
            .await?
            .take(MAX_ADDRESSES + 1)
            .collect(),
    };
    if addresses.len() > MAX_ADDRESSES
        || addresses.iter().any(|address| {
            let ip = address.ip().to_canonical();
            ip.is_unspecified()
                || ip.is_multicast()
                || ip == std::net::Ipv4Addr::BROADCAST
                || (ip.is_loopback() && !node.endpoints.allow_loopback)
        })
    {
        return Err(failed());
    }
    let ipv4 = endpoint.local_addr()?.is_ipv4();
    addresses
        .into_iter()
        .find(|address| address.is_ipv4() == ipv4)
        .ok_or_else(failed)
}

#[allow(clippy::too_many_arguments)]
async fn probe(
    node: String,
    group: Group,
    session: Option<Session>,
    endpoint: quinn::Endpoint,
    control: Arc<NodeControl>,
    selector: Arc<RelaySelector>,
    identity: Arc<NodeIdentity>,
    not_before: Deadline,
    failures: u8,
) -> Outcome {
    let validity = group.work.clone();
    let result = tokio::select! { biased;
        _ = work_stopped(&control, &validity) => return Outcome { node, session: None, observations: Vec::new(), next_at: Deadline::now() + PERIOD, failures: 0 },
        result = async {
            tokio::time::sleep_until(not_before).await;
            let started = Deadline::now();
            let result = tokio::time::timeout(PROBE_BUDGET, exchange(group, session, endpoint, control.clone(), selector, identity)).await;
            (started, result)
        } => result,
    };
    match result {
        (started, Ok(Ok((session, observations)))) if started.elapsed() < PROBE_BUDGET => Outcome {
            node,
            session: Some(session),
            observations,
            next_at: started + PERIOD,
            failures: 0,
        },
        _ => Outcome {
            node,
            session: None,
            observations: Vec::new(),
            next_at: Deadline::now() + Duration::from_secs(1u64 << failures.min(3)),
            failures: failures.saturating_add(1),
        },
    }
}

async fn exchange(
    group: Group,
    session: Option<Session>,
    endpoint: quinn::Endpoint,
    control: Arc<NodeControl>,
    selector: Arc<RelaySelector>,
    identity: Arc<NodeIdentity>,
) -> io::Result<(Session, Vec<Observation>)> {
    if group.work.is_empty()
        || group.work.len() > MAX_SPACES
        || group.work.iter().any(|work| !current(&control, work))
    {
        return Err(failed());
    }
    let mut session = match session.filter(|session| {
        session.key == group.key
            && same_work(&session.work, &group.work)
            && session.connection.close_reason().is_none()
    }) {
        Some(session) => session,
        None => {
            let address = address(&endpoint, &group.key.node).await?;
            let slot = selector.socket(address.ip())?;
            let config = topology_node_client_config(&identity, digest(&group.key.public_key))
                .map_err(io::Error::other)?;
            let connection = endpoint
                .connect_with(config, address, "peer.nestlink.invalid")
                .map_err(io::Error::other)?
                .await
                .map_err(io::Error::other)?;
            let mut opening = Opening(Some(connection.clone()));
            if authenticated_peer_fingerprint(&connection)? != digest(&group.key.public_key) {
                return Err(failed());
            }
            let (write, read) = connection.open_bi().await.map_err(io::Error::other)?;
            let session = Session {
                key: group.key.clone(),
                work: group.work.clone(),
                connection,
                write,
                read,
                _slot: slot,
            };
            // The Session takes the same authenticated connection and close duty.
            opening.0 = None;
            session
        }
    };
    let requests: Vec<_> = group
        .work
        .iter()
        .map(|work| NetworkTopologyProbe {
            schema_version: 1,
            space_id: work.space.clone(),
            publisher_digest: work.authority.publisher_digest,
            local_endpoint_revision: work.authority.local.revision,
            remote_endpoint_revision: work.neighbor.node.revision,
            nonce: random_bytes::<32>(),
        })
        .collect();
    // A bounded pipeline shares one stream across all permitted spaces on this
    // same peer. It avoids one RTT (or connection) per space in the 700ms budget.
    for request in &requests {
        write_message(&mut session.write, request).await?;
    }
    for (request, work) in requests.iter().zip(&group.work) {
        let response: NetworkTopologyProbe = tokio::select! { biased;
            _ = session.connection.read_datagram() => return Err(failed()),
            _ = session.connection.accept_bi() => return Err(failed()),
            _ = session.connection.accept_uni() => return Err(failed()),
            response = read_message(&mut session.read) => response?,
        };
        if response.schema_version != 1
            || response.space_id != request.space_id
            || response.publisher_digest != work.neighbor.publisher_digest
            || response.nonce != request.nonce
            || response.local_endpoint_revision != request.remote_endpoint_revision
            || response.remote_endpoint_revision != request.local_endpoint_revision
        {
            return Err(failed());
        }
    }
    if session.connection.close_reason().is_some()
        || group.work.iter().any(|work| !current(&control, work))
    {
        return Err(failed());
    }
    session.work = group.work.clone();
    let completed = Deadline::now();
    Ok((
        session,
        group
            .work
            .into_iter()
            .map(|work| Observation { work, completed })
            .collect(),
    ))
}

/// A TLS-authenticated peer may exchange only this fixed bounded message on
/// the independent ALPN. Current metadata is checked before and after each echo.
pub(super) async fn incoming(
    connection: quinn::Connection,
    control: Arc<NodeControl>,
    identity: Arc<NodeIdentity>,
) -> io::Result<()> {
    let peer = authenticated_peer_fingerprint(&connection)?;
    let (mut write, mut read) = tokio::time::timeout(PROBE_BUDGET, connection.accept_bi())
        .await
        .map_err(io::Error::other)?
        .map_err(io::Error::other)?;
    let mut stopped = control.stopped();
    let mut window = Deadline::now();
    let mut messages = 0u16;
    let mut bindings = BTreeMap::<String, NetworkNodeTopologyAuthority>::new();
    loop {
        if *stopped.borrow() {
            return Err(failed());
        }
        let request: NetworkTopologyProbe = tokio::select! { biased;
            _ = stopped.changed() => return Err(failed()),
            _ = peer_stopped(&control, &peer) => return Err(failed()),
            _ = connection.read_datagram() => return Err(failed()),
            _ = connection.accept_bi() => return Err(failed()),
            _ = connection.accept_uni() => return Err(failed()),
            request = tokio::time::timeout(Duration::from_millis(1500), read_message(&mut read)) => request.map_err(io::Error::other)??,
        };
        if window.elapsed() >= Duration::from_secs(1) {
            window = Deadline::now();
            messages = 0;
        }
        messages += 1;
        if messages > 256
            || request.schema_version != 1
            || request.nonce == [0; 32]
            || !nestlink_protocol::valid_id(&request.space_id)
        {
            return Err(failed());
        }
        let authority = control
            .network_topology_authority(&request.space_id)
            .map_err(|_| failed())?;
        if bindings
            .get(&request.space_id)
            .is_some_and(|original| !same_authority(original, &authority))
            || (!bindings.contains_key(&request.space_id) && bindings.len() >= MAX_SPACES)
        {
            return Err(failed());
        }
        bindings.insert(request.space_id.clone(), authority.clone());
        let neighbor = authority
            .neighbors
            .iter()
            .find(|neighbor| digest(&neighbor.public_key) == peer)
            .ok_or_else(failed)?;
        let claims =
            nestlink_protocol::network_topology::TopologyPublisherClaims::decode_canonical(
                &authority.publisher.claims,
            )
            .map_err(io::Error::other)?;
        if claims.public_key != identity.public_key()
            || claims.peer != PeerId::from_public_key(&identity.public_key())
            || request.publisher_digest != neighbor.publisher_digest
            || request.local_endpoint_revision != neighbor.node.revision
            || request.remote_endpoint_revision != authority.local.revision
        {
            return Err(failed());
        }
        let response = NetworkTopologyProbe {
            schema_version: 1,
            space_id: request.space_id.clone(),
            publisher_digest: authority.publisher_digest,
            local_endpoint_revision: authority.local.revision,
            remote_endpoint_revision: neighbor.node.revision,
            nonce: request.nonce,
        };
        if !same_authority(
            &control
                .network_topology_authority(&request.space_id)
                .map_err(|_| failed())?,
            &authority,
        ) {
            return Err(failed());
        }
        tokio::time::timeout(PROBE_BUDGET, write_message(&mut write, &response))
            .await
            .map_err(io::Error::other)??;
        if !same_authority(
            &control
                .network_topology_authority(&request.space_id)
                .map_err(|_| failed())?,
            &authority,
        ) {
            return Err(failed());
        }
    }
}
