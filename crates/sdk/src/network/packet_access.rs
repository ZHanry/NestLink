//! Raw IP business admission. A verified path or space membership alone never
//! permits an OS/LAN injection. Both endpoint owners run this same policy.
mod online;
mod parse;
pub use online::OnlinePacketAccess;
#[cfg(test)]
mod tests;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ipnet::IpNet;
use nestlink_identity::network::{
    NetworkVerification, VerifiedMembership, VerifiedNetworkGrant, VerifiedNetworkPath,
};
use nestlink_protocol::{
    network::{Direction, GrantClaims, IpPrefix, IpProtocol, NetworkAccessClaims, PeerId, Purpose},
    spaces::addressing::SpaceAddressDirectory,
};
use std::{
    collections::BTreeMap,
    io,
    net::IpAddr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// The TUN uses the IPv6 minimum MTU. Carrier fragmentation happens below the
/// inner QUIC connection and does not turn an IP fragment into authorized data.
pub const PACKET_MTU: usize = 1280;
const MAX_FLOWS: usize = 1024;
const FLOW_IDLE: Duration = Duration::from_secs(30);
const DIRECTORY_FRESHNESS: Duration = Duration::from_secs(5);

/// Direction is defined relative to the signed NetworkAccess destination:
/// Inbound is source -> destination; Outbound is destination -> source.
/// This definition is identical at both endpoints and independent of which
/// process happened to dial the physical carrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketDirection {
    SourceToDestination,
    DestinationToSource,
}
impl PacketDirection {
    fn rule(self) -> Direction {
        match self {
            Self::SourceToDestination => Direction::Inbound,
            Self::DestinationToSource => Direction::Outbound,
        }
    }
    fn reverse(self) -> Self {
        match self {
            Self::SourceToDestination => Self::DestinationToSource,
            Self::DestinationToSource => Self::SourceToDestination,
        }
    }
}

/// Prefix ownership is independent from NetworkAccess. Host addresses must be
/// the current identity-bound directory assignment; a larger prefix requires a
/// separately signed RouteExport for this exact peer and space.
#[derive(Clone)]
pub struct PacketPeerAuthority {
    member: VerifiedMembership,
    address_epoch: u64,
    directory_revision: u64,
    hosts: [IpAddr; 2],
    exports: Vec<VerifiedNetworkGrant>,
    prefixes: Vec<IpNet>,
    fresh_until: Instant,
}
impl PacketPeerAuthority {
    /// `directory` must be freshly obtained from the pinned management origin,
    /// never from a peer or an untrusted file. Freshness is bounded again here;
    /// the live owner must continuously refresh and compare its revision.
    pub fn from_directory(
        context: &NetworkVerification<'_>,
        member: VerifiedMembership,
        directory: &SpaceAddressDirectory,
        exports: Vec<VerifiedNetworkGrant>,
    ) -> io::Result<Self> {
        let current = current(context)?;
        let context = &current;
        member.check_current(context).map_err(denied)?;
        let space = &directory.space;
        let observed = space.observed_at_unix_ms;
        if space.space_id != context.space_id
            || space.deployment_id != context.deployment_id
            || space.policy_epoch != context.policy_epoch
            || space.archived
            || space.authority_public_key != URL_SAFE_NO_PAD.encode(context.authority_key)
            || directory.cache_max_age_seconds != 0
            || directory.addresses.len() > 4096
            || exports.len() > 32
            || observed > context.now_ms
            || context.now_ms - observed >= DIRECTORY_FRESHNESS.as_millis() as u64
        {
            return Err(denied(
                "raw IP address directory is stale or outside the pinned space",
            ));
        }
        let mut rows = directory
            .addresses
            .iter()
            .filter(|row| row.installation_id == member.claims().installation_id);
        let row = rows
            .next()
            .ok_or_else(|| denied("peer has no current virtual address"))?;
        if rows.next().is_some()
            || !row.active
            || row.revoked
            || row.reserved
            || row.address_epoch == 0
            || row.membership_epoch != member.claims().membership_epoch
            || row.public_key != URL_SAFE_NO_PAD.encode(member.claims().public_key)
        {
            return Err(denied(
                "virtual address identity or membership binding changed",
            ));
        }
        let v4: std::net::Ipv4Addr = row.ipv4.parse().map_err(denied)?;
        let v6: std::net::Ipv6Addr = row.ipv6.parse().map_err(denied)?;
        let pool4: ipnet::Ipv4Net = directory.ipv4_pool.parse().map_err(denied)?;
        let pool6: ipnet::Ipv6Net = directory.ipv6_pool.parse().map_err(denied)?;
        if row.ipv4 != v4.to_string()
            || row.ipv6 != v6.to_string()
            || !pool4.contains(&v4)
            || !pool6.contains(&v6)
        {
            return Err(denied(
                "virtual address is not canonical or inside its managed pool",
            ));
        }
        let hosts = [IpAddr::V4(v4), IpAddr::V6(v6)];
        let mut prefixes = vec![
            prefix(IpPrefix {
                network: hosts[0],
                prefix_len: 32,
            })?,
            prefix(IpPrefix {
                network: hosts[1],
                prefix_len: 128,
            })?,
        ];
        for export in &exports {
            export.check_current(context).map_err(denied)?;
            let GrantClaims::RouteExport(claims) = export.claims() else {
                return Err(denied(
                    "additional source prefixes require RouteExport authority",
                ));
            };
            if claims.gateway != member.peer() {
                return Err(denied(
                    "RouteExport belongs to a different authenticated peer",
                ));
            }
            for value in &claims.prefixes {
                let value = prefix(*value)?;
                if !prefixes.contains(&value) {
                    prefixes.push(value);
                }
            }
        }
        let remaining = DIRECTORY_FRESHNESS
            .checked_sub(Duration::from_millis(context.now_ms - observed))
            .ok_or_else(|| denied("virtual address observation expired"))?;
        Ok(Self {
            member,
            address_epoch: row.address_epoch,
            directory_revision: directory.revision,
            hosts,
            exports,
            prefixes,
            fresh_until: Instant::now() + remaining,
        })
    }
    pub fn peer(&self) -> PeerId {
        self.member.peer()
    }
    pub fn host_addresses(&self) -> [IpAddr; 2] {
        self.hosts
    }
    fn check_current(&self, context: &NetworkVerification<'_>) -> io::Result<()> {
        if Instant::now() >= self.fresh_until {
            return Err(denied("virtual address observation expired"));
        }
        self.member.check_current(context).map_err(denied)?;
        for export in &self.exports {
            export.check_current(context).map_err(denied)?;
        }
        Ok(())
    }
    fn accepts_successor(&self, next: &Self) -> bool {
        self.peer() == next.peer()
            && self.member.digest() == next.member.digest()
            && self.address_epoch == next.address_epoch
            && self.hosts == next.hosts
            && next.directory_revision >= self.directory_revision
            && self
                .exports
                .iter()
                .map(VerifiedNetworkGrant::digest)
                .eq(next.exports.iter().map(VerifiedNetworkGrant::digest))
    }
    fn contains(&self, address: IpAddr) -> bool {
        self.prefixes.iter().any(|value| value.contains(&address))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct FlowKey {
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    source_port: u16,
    destination_port: u16,
}
impl FlowKey {
    fn reverse(&self) -> Self {
        Self {
            source: self.destination,
            destination: self.source,
            protocol: self.protocol,
            source_port: self.destination_port,
            destination_port: self.source_port,
        }
    }
}
struct Flow {
    initiated: PacketDirection,
    expires: Instant,
    tcp: bool,
    established: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketAdmission {
    pub direction: PacketDirection,
    pub bytes: usize,
    pub reply: bool,
}

/// One non-cloneable business budget and bounded reply table. The ordinary
/// process owns this state; no unchecked raw packet reaches its TUN helper.
pub struct VerifiedPacketAccess {
    path: VerifiedNetworkPath,
    connectivity: VerifiedNetworkGrant,
    access: VerifiedNetworkGrant,
    claims: NetworkAccessClaims,
    source: PacketPeerAuthority,
    destination: PacketPeerAuthority,
    local: PeerId,
    deadline: Instant,
    spent: u64,
    flows: BTreeMap<FlowKey, Flow>,
    stopped: bool,
}
impl VerifiedPacketAccess {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        context: &NetworkVerification<'_>,
        path: VerifiedNetworkPath,
        connectivity: VerifiedNetworkGrant,
        access: VerifiedNetworkGrant,
        local: PeerId,
        source: PacketPeerAuthority,
        destination: PacketPeerAuthority,
    ) -> io::Result<Self> {
        let current = current(context)?;
        let context = &current;
        path.check_current(context).map_err(denied)?;
        connectivity.check_current(context).map_err(denied)?;
        access.check_current(context).map_err(denied)?;
        source.check_current(context)?;
        destination.check_current(context)?;
        let GrantClaims::NetworkAccess(claims) = access.claims() else {
            return Err(denied(
                "a separately verified NetworkAccess grant is required",
            ));
        };
        let GrantClaims::Connectivity(connection) = connectivity.claims() else {
            return Err(denied(
                "a separately verified Connectivity grant is required",
            ));
        };
        if path.purpose() != Purpose::NetworkPacket
            || connection.purpose != Purpose::NetworkPacket
            || connection.business_grant_digest != access.digest()
            || path.claims().connectivity_grant_digest != connectivity.digest()
            || connection.peers != path.peers()
            || !path.peers().contains(claims.source)
            || !path.peers().contains(claims.destination)
            || !path.peers().contains(local)
            || source.peer() != claims.source
            || destination.peer() != claims.destination
            || connection.scope.not_before_ms < claims.scope.not_before_ms
            || connection.scope.expires_at_ms > claims.scope.expires_at_ms
        {
            return Err(denied(
                "raw IP path, business digest or prefix owner mismatch",
            ));
        }
        let remaining = path
            .claims()
            .scope
            .expires_at_ms
            .checked_sub(context.now_ms)
            .filter(|value| *value > 0)
            .ok_or_else(|| denied("raw IP path expired"))?;
        let claims = claims.clone();
        Ok(Self {
            path,
            connectivity,
            access,
            claims,
            source,
            destination,
            local,
            deadline: Instant::now() + Duration::from_millis(remaining),
            spent: 0,
            flows: BTreeMap::new(),
            stopped: false,
        })
    }
    pub fn business_digest(&self) -> [u8; 32] {
        self.access.digest()
    }
    pub fn local_peer(&self) -> PeerId {
        self.local
    }
    pub fn remote_peer(&self) -> PeerId {
        if self.local == self.claims.source {
            self.claims.destination
        } else {
            self.claims.source
        }
    }
    pub fn spent_bytes(&self) -> u64 {
        self.spent
    }
    pub fn stop(&mut self) {
        self.stopped = true;
        self.flows.clear();
    }
    /// Refresh only the original assignment. An observation gap, epoch change,
    /// replaced membership or removed export permanently stops this owner.
    pub fn refresh_addresses(
        &mut self,
        context: &NetworkVerification<'_>,
        source: PacketPeerAuthority,
        destination: PacketPeerAuthority,
    ) -> io::Result<()> {
        let current = current(context)?;
        let context = &current;
        if let Err(error) = self.check_live(context) {
            self.stop();
            return Err(error);
        }
        if let Err(error) = source
            .check_current(context)
            .and_then(|()| destination.check_current(context))
        {
            self.stop();
            return Err(error);
        }
        if !self.source.accepts_successor(&source)
            || !self.destination.accepts_successor(&destination)
        {
            self.stop();
            return Err(denied("raw IP address ownership changed"));
        }
        self.source = source;
        self.destination = destination;
        Ok(())
    }
    fn check_live(&self, context: &NetworkVerification<'_>) -> io::Result<()> {
        if self.stopped || Instant::now() >= self.deadline {
            return Err(denied("raw IP business owner stopped or expired"));
        }
        self.path.check_current(context).map_err(denied)?;
        self.connectivity.check_current(context).map_err(denied)?;
        self.access.check_current(context).map_err(denied)?;
        self.source.check_current(context)?;
        self.destination.check_current(context)
    }
    /// Called on packets read from the owned TUN before transmitting them.
    pub fn admit_local(
        &mut self,
        context: &NetworkVerification<'_>,
        bytes: &[u8],
    ) -> io::Result<PacketAdmission> {
        self.admit(context, self.local, bytes)
    }
    /// `authenticated_peer` comes from the endpoint-pinned carrier, never the
    /// packet payload. The returned admission is required before OS injection.
    pub fn admit_remote(
        &mut self,
        context: &NetworkVerification<'_>,
        authenticated_peer: PeerId,
        bytes: &[u8],
    ) -> io::Result<PacketAdmission> {
        if authenticated_peer != self.remote_peer() {
            return Err(denied(
                "raw packet arrived from a different authenticated peer",
            ));
        }
        self.admit(context, authenticated_peer, bytes)
    }
    fn admit(
        &mut self,
        context: &NetworkVerification<'_>,
        sender: PeerId,
        bytes: &[u8],
    ) -> io::Result<PacketAdmission> {
        let current = current(context)?;
        let context = &current;
        if let Err(error) = self.check_live(context) {
            self.stop();
            return Err(error);
        }
        let packet = parse::packet(bytes)?;
        let direction = if sender == self.claims.source {
            PacketDirection::SourceToDestination
        } else if sender == self.claims.destination {
            PacketDirection::DestinationToSource
        } else {
            return Err(denied("raw packet sender is outside the business pair"));
        };
        let (source, destination, approved_source, approved_destination) = match direction {
            PacketDirection::SourceToDestination => (
                &self.claims.source_prefixes,
                &self.claims.destination_prefixes,
                &self.source,
                &self.destination,
            ),
            PacketDirection::DestinationToSource => (
                &self.claims.destination_prefixes,
                &self.claims.source_prefixes,
                &self.destination,
                &self.source,
            ),
        };
        if !approved_source.contains(packet.key.source)
            || !approved_destination.contains(packet.key.destination)
            || !contains(source, packet.key.source)?
            || !contains(destination, packet.key.destination)?
        {
            return Err(denied(
                "raw packet source or destination prefix is not assigned and authorized",
            ));
        }
        let now = Instant::now();
        self.flows.retain(|_, flow| now < flow.expires);
        let reverse = packet.key.reverse();
        // An ICMP request can collide with the reversed id/sequence key of an
        // admitted request. It is a new request and needs its own direction
        // rule; only an EchoReply may use the original request's reply right.
        let reverse_flow = self
            .flows
            .get(&reverse)
            .filter(|flow| flow.initiated == direction.reverse() && !packet.echo_request);
        let reply = reverse_flow.is_some();
        let direct = self.claims.rules.iter().any(|rule| {
            rule.direction == direction.rule()
                && rule.protocol == packet.protocol
                && match rule.ports {
                    Some([low, high]) => (low..=high).contains(&packet.key.destination_port),
                    None => packet.echo_request,
                }
        });
        let existing = self
            .flows
            .get(&packet.key)
            .is_some_and(|flow| flow.initiated == direction);
        if (!direct && !reply && !existing)
            || (packet.tcp && !existing && !reply && (!packet.syn || packet.ack))
            || (packet.tcp && reply && packet.syn && !packet.ack)
            || (packet.echo_reply && !reply)
            || (reply
                && reverse_flow.is_some_and(|flow| flow.tcp && !flow.established)
                && !(packet.syn && packet.ack || packet.rst))
        {
            return Err(denied(
                "raw packet transport direction, destination port or reply state is unauthorized",
            ));
        }
        let spent = self
            .spent
            .checked_add(bytes.len() as u64)
            .filter(|value| *value <= self.claims.byte_limit)
            .ok_or_else(|| denied("raw IP cumulative byte quota exhausted"))?;
        if !reply && !existing && self.flows.len() >= MAX_FLOWS {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "raw IP reply table is full",
            ));
        }
        if reply {
            if let Some(flow) = self.flows.get_mut(&reverse) {
                flow.established = true;
            }
        } else if !packet.rst && !packet.fin {
            let flow = self.flows.entry(packet.key.clone()).or_insert(Flow {
                initiated: direction,
                expires: now,
                tcp: packet.tcp,
                established: !packet.tcp,
            });
            // A peer's unsolicited reply cannot extend the original request's
            // authority. Only activity in the authorized original direction can.
            flow.expires = (now + FLOW_IDLE).min(self.deadline);
        }
        if packet.rst {
            self.flows.remove(&packet.key);
            self.flows.remove(&reverse);
        } else if packet.fin {
            // Keep the final ACK and the other endpoint's FIN inside the same
            // bounded flow. Removing state at the first FIN breaks normal OS
            // TCP shutdown; neither direction gains a new initiating right.
            let closing = now + Duration::from_secs(5);
            for key in [&packet.key, &reverse] {
                if let Some(flow) = self.flows.get_mut(key) {
                    flow.expires = flow.expires.min(closing);
                }
            }
        }
        self.spent = spent;
        Ok(PacketAdmission {
            direction,
            bytes: bytes.len(),
            reply,
        })
    }
}

fn prefix(value: IpPrefix) -> io::Result<IpNet> {
    value.validate().map_err(denied)?;
    IpNet::new(value.network, value.prefix_len).map_err(denied)
}
fn contains(prefixes: &[IpPrefix], address: IpAddr) -> io::Result<bool> {
    for value in prefixes {
        if prefix(*value)?.contains(&address) {
            return Ok(true);
        }
    }
    Ok(false)
}
fn denied(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, error.to_string())
}
fn current<'a>(context: &NetworkVerification<'a>) -> io::Result<NetworkVerification<'a>> {
    let wall: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(denied)?
        .as_millis()
        .try_into()
        .map_err(denied)?;
    Ok(NetworkVerification {
        authority_key: context.authority_key,
        deployment_id: context.deployment_id,
        space_id: context.space_id,
        policy_epoch: context.policy_epoch,
        now_ms: wall.max(context.now_ms),
        revoked_grant_ids: context.revoked_grant_ids,
    })
}
