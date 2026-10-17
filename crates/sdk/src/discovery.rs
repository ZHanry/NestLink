//! Actual OS interface and same-socket STUN candidates. Relay-only performs no probes.
use crate::SdkError;
use nestlink_identity::VerifiedPermit;
use nestlink_protocol::{
    Path,
    api::{Candidate, CandidateKind, Transport},
    signaling::safe_peer_address,
};
use nestlink_transport_quic::discovery::DiscoverySocket;
use quinn::AsyncUdpSocket;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

pub struct Gathered {
    pub network_generation: u64,
    pub candidates: Vec<Candidate>,
    pub failed_stun: Vec<SocketAddr>,
}
/// Configured STUN servers must be explicitly trusted by the deployment administrator.
/// OS addresses are only candidate facts; mutual endpoint TLS still proves ownership.
pub async fn gather(
    permit: &VerifiedPermit,
    socket: Arc<DiscoverySocket>,
    stun_servers: Vec<SocketAddr>,
) -> Result<Gathered, SdkError> {
    let generation = socket.generation();
    let mut result = Gathered {
        network_generation: generation,
        candidates: vec![],
        failed_stun: vec![],
    };
    if !permit.claims().paths.contains(&(Path::Direct as i32)) {
        return Ok(result);
    }
    if stun_servers.len() > 4 {
        return Err(SdkError::Invalid);
    }
    let bound = socket.local_addr().map_err(|_| SdkError::Invalid)?;
    let interfaces = tokio::task::spawn_blocking(if_addrs::get_if_addrs)
        .await
        .map_err(|_| SdkError::Invalid)?
        .map_err(|_| SdkError::Invalid)?;
    for interface in interfaces {
        let ip = interface.ip();
        if !safe_peer_address(ip)
            || interface.is_loopback()
            || !interface.is_oper_up()
            || ip.is_ipv4() != bound.is_ipv4()
            || (!bound.ip().is_unspecified() && ip != bound.ip())
        {
            continue;
        }
        let kind = match ip {
            IpAddr::V4(ip) if ip.is_private() => CandidateKind::Lan,
            IpAddr::V6(_) => CandidateKind::Ipv6,
            _ => CandidateKind::Reflexive,
        };
        result.candidates.push(Candidate {
            address: SocketAddr::new(ip, bound.port()),
            kind,
            transport: Transport::Quic,
            generation,
        });
    }
    let mut tasks = tokio::task::JoinSet::new();
    for server in stun_servers {
        let socket = socket.clone();
        tasks.spawn(async move { (server, socket.probe(server, Duration::from_secs(2)).await) });
    }
    while let Some(task) = tasks.join_next().await {
        let (server, observation) = task.map_err(|_| SdkError::Invalid)?;
        match observation {
            Ok(observation)
                if observation.network_generation == generation
                    && safe_peer_address(observation.reflexive.ip()) =>
            {
                result.candidates.push(Candidate {
                    address: observation.reflexive,
                    kind: CandidateKind::Reflexive,
                    transport: Transport::Quic,
                    generation,
                });
            }
            _ => result.failed_stun.push(server),
        }
    }
    if socket.generation() != generation {
        return Err(SdkError::Invalid);
    }
    result.candidates.sort_by_key(|c| (c.kind, c.address));
    result
        .candidates
        .dedup_by(|a, b| a.address == b.address && a.transport == b.transport);
    result
        .candidates
        .truncate(nestlink_protocol::CANDIDATE_COUNT as usize);
    Ok(result)
}
