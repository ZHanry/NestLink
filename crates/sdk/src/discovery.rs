//! Actual OS interface and same-socket STUN candidates. Relay-only performs no probes.
use crate::SdkError;
use crate::native::AddressPolicy;
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
    sync::{Arc, Weak},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug)]
pub enum CandidateSource {
    Interface {
        index: u32,
        luid: u64,
        name: String,
    },
    Stun {
        server: SocketAddr,
        local: SocketAddr,
    },
}
#[derive(Clone, Debug)]
pub struct CandidateFact {
    pub candidate: Candidate,
    pub source: CandidateSource,
    expires_at: Instant,
}

pub struct Gathered {
    pub network_generation: u64,
    pub candidates: Vec<Candidate>,
    pub failed_stun: Vec<SocketAddr>,
    facts: Vec<CandidateFact>,
    permit_digest: [u8; 32],
    permit_issuer: [u8; 32],
    observed_wall_ms: u64,
    deadline: Instant,
    socket: Weak<DiscoverySocket>,
}
impl Gathered {
    pub fn facts(&self) -> &[CandidateFact] {
        &self.facts
    }
    /// Reusing this result never restarts its original socket/permit/TTL budget.
    pub fn check_current(
        &self,
        permit: &VerifiedPermit,
        socket: &DiscoverySocket,
    ) -> Result<(), SdkError> {
        let now = wall_ms()?;
        if self
            .socket
            .upgrade()
            .is_none_or(|owner| !std::ptr::eq(Arc::as_ptr(&owner), socket))
            || self.permit_digest != permit.digest()
            || self.permit_issuer != permit.issuer()
            || self.network_generation != socket.generation()
            || Instant::now() >= self.deadline
            || self
                .facts
                .iter()
                .any(|fact| Instant::now() >= fact.expires_at)
            || now < self.observed_wall_ms
            || now >= permit.claims().expires_at_unix_ms
            || self.candidates.len() != self.facts.len()
            || self
                .candidates
                .iter()
                .zip(&self.facts)
                .any(|(candidate, fact)| candidate != &fact.candidate)
        {
            return Err(SdkError::Invalid);
        }
        socket.check_path().map_err(|_| SdkError::Invalid)?;
        if self
            .facts
            .iter()
            .any(|fact| matches!(&fact.source, CandidateSource::Interface { .. }))
        {
            let interfaces = socket
                .candidate_interfaces()
                .map_err(|_| SdkError::Invalid)?;
            if self.facts.iter().any(|fact| match &fact.source {
                CandidateSource::Interface { index, luid, name } => {
                    !interfaces.iter().any(|interface| {
                        interface.index == *index
                            && interface.luid == *luid
                            && interface.name == *name
                            && interface.addresses.contains(&fact.candidate.address.ip())
                    })
                }
                CandidateSource::Stun { .. } => false,
            }) {
                return Err(SdkError::Invalid);
            }
        }
        Ok(())
    }
}
fn wall_ms() -> Result<u64, SdkError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SdkError::Invalid)?
        .as_millis()
        .try_into()
        .map_err(|_| SdkError::Invalid)
}
/// Configured STUN servers must be explicitly trusted by the deployment administrator.
/// OS addresses are only candidate facts; mutual endpoint TLS still proves ownership.
pub async fn gather(
    permit: &VerifiedPermit,
    socket: Arc<DiscoverySocket>,
    stun_servers: Vec<SocketAddr>,
) -> Result<Gathered, SdkError> {
    let policy = AddressPolicy::new(&[]).map_err(|_| SdkError::Invalid)?;
    gather_with_policy(permit, socket, stun_servers, &policy).await
}

pub async fn gather_with_policy(
    permit: &VerifiedPermit,
    socket: Arc<DiscoverySocket>,
    stun_servers: Vec<SocketAddr>,
    policy: &AddressPolicy,
) -> Result<Gathered, SdkError> {
    let now = wall_ms()?;
    if permit.claims().issued_at_unix_ms > now || permit.claims().expires_at_unix_ms <= now {
        return Err(SdkError::Invalid);
    }
    let deadline = Instant::now()
        + Duration::from_millis((permit.claims().expires_at_unix_ms - now).min(5_000));
    let generation = socket.generation();
    let mut result = Gathered {
        network_generation: generation,
        candidates: vec![],
        failed_stun: vec![],
        facts: Vec::new(),
        permit_digest: permit.digest(),
        permit_issuer: permit.issuer(),
        observed_wall_ms: now,
        deadline,
        socket: Arc::downgrade(&socket),
    };
    if !permit.claims().paths.contains(&(Path::Direct as i32)) {
        return Ok(result);
    }
    if stun_servers.len() > 4 {
        return Err(SdkError::Invalid);
    }
    let bound = socket.local_addr().map_err(|_| SdkError::Invalid)?;
    let current = socket.clone();
    let interfaces = tokio::task::spawn_blocking(move || current.candidate_interfaces())
        .await
        .map_err(|_| SdkError::Invalid)?
        .map_err(|_| SdkError::Invalid)?;
    for interface in interfaces {
        for ip in interface.addresses {
            if !safe_peer_address(ip)
                || !policy.allows(ip)
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
            result.facts.push(CandidateFact {
                candidate: Candidate {
                    address: SocketAddr::new(ip, bound.port()),
                    kind,
                    transport: Transport::Quic,
                    generation,
                },
                source: CandidateSource::Interface {
                    index: interface.index,
                    luid: interface.luid,
                    name: interface.name.clone(),
                },
                expires_at: deadline,
            });
        }
    }
    let mut tasks = tokio::task::JoinSet::new();
    for server in stun_servers {
        let socket = socket.clone();
        let budget = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(2));
        tasks.spawn(async move { (server, socket.probe(server, budget).await) });
    }
    while let Some(task) = tasks.join_next().await {
        let (server, observation) = task.map_err(|_| SdkError::Invalid)?;
        match observation {
            Ok(observation)
                if observation.network_generation == generation
                    && safe_peer_address(observation.reflexive.ip())
                    && policy.allows(observation.reflexive.ip())
                    && observation.check_current(&socket).is_ok() =>
            {
                result.facts.push(CandidateFact {
                    candidate: Candidate {
                        address: observation.reflexive,
                        kind: CandidateKind::Reflexive,
                        transport: Transport::Quic,
                        generation,
                    },
                    source: CandidateSource::Stun {
                        server: observation.server,
                        local: observation.local,
                    },
                    expires_at: observation.expires_at.min(deadline),
                });
            }
            _ => result.failed_stun.push(server),
        }
    }
    result
        .facts
        .sort_by_key(|fact| (fact.candidate.kind, fact.candidate.address));
    result.facts.dedup_by(|a, b| {
        a.candidate.address == b.candidate.address && a.candidate.transport == b.candidate.transport
    });
    result
        .facts
        .truncate(nestlink_protocol::CANDIDATE_COUNT as usize);
    result.candidates = result
        .facts
        .iter()
        .map(|fact| fact.candidate.clone())
        .collect();
    result.check_current(permit, &socket)?;
    Ok(result)
}

#[cfg(test)]
mod tests;
