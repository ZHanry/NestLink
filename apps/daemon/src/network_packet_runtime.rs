//! One ordinary-user packet authorization/carrier loop for host and subnet
//! owners. Platform adapters supply complete packets and exact owner checks.
//! This module never creates an online start, replaces its owner or its budget.
use nestlink_sdk::{Sdk, network::packet_access::{OnlinePacketAccess, PacketAdmission, PACKET_MTU}};
#[cfg(target_os = "linux")]
use nestlink_sdk::{DeviceIdentity, network::wireguard::OnlineWireGuardClient};
use nestlink_transport_quic::packet_codec::{DirectPacketEndpoint, PacketAssembler, encode_direct};
use serde::Serialize;
use std::{future::Future, io, net::SocketAddr, pin::Pin, time::Duration};
use tokio::time::Instant;

pub(crate) type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub(crate) type PacketIoFuture<'a> = Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>>;
pub(crate) type GuardFuture<'a> = Pin<Box<dyn Future<Output = Result> + Send + 'a>>;
/// Both host/subnet and standard WireGuard ingress retain the same original
/// noncloneable one-use packet admission owner. This adapter only supplies the
/// extra local identity needed to refresh a separately signed WG key binding.
pub(crate) trait PacketAuthority {
    fn business_digest(&self) -> [u8; 32];
    fn transport_group(&self) -> [u8; 32];
    fn wire_direction(&self) -> nestlink_protocol::network_datagram::Direction;
    fn remaining_lifetime(&self) -> Duration;
    fn spent_bytes(&self) -> u64;
    fn stop(&mut self);
    fn admit_local(&mut self, packet: &[u8]) -> io::Result<PacketAdmission>;
    fn admit_remote(&mut self, packet: &[u8]) -> io::Result<PacketAdmission>;
    fn refresh<'a>(&'a mut self, sdk: &'a Sdk) -> GuardFuture<'a>;
}
impl PacketAuthority for OnlinePacketAccess {
    fn business_digest(&self) -> [u8; 32] { OnlinePacketAccess::business_digest(self) }
    fn transport_group(&self) -> [u8; 32] { OnlinePacketAccess::transport_group(self) }
    fn wire_direction(&self) -> nestlink_protocol::network_datagram::Direction { OnlinePacketAccess::wire_direction(self) }
    fn remaining_lifetime(&self) -> Duration { OnlinePacketAccess::remaining_lifetime(self) }
    fn spent_bytes(&self) -> u64 { OnlinePacketAccess::spent_bytes(self) }
    fn stop(&mut self) { OnlinePacketAccess::stop(self) }
    fn admit_local(&mut self, packet: &[u8]) -> io::Result<PacketAdmission> { OnlinePacketAccess::admit_local(self, packet) }
    fn admit_remote(&mut self, packet: &[u8]) -> io::Result<PacketAdmission> { OnlinePacketAccess::admit_remote(self, packet) }
    fn refresh<'a>(&'a mut self, sdk: &'a Sdk) -> GuardFuture<'a> { Box::pin(async move { OnlinePacketAccess::refresh(self, sdk).await.map_err(Into::into) }) }
}
#[cfg(target_os = "linux")]
pub(crate) struct WireGuardAuthority<'a> {
    pub owner: &'a mut OnlineWireGuardClient,
    pub local: &'a DeviceIdentity,
}
#[cfg(target_os = "linux")]
impl PacketAuthority for WireGuardAuthority<'_> {
    fn business_digest(&self) -> [u8; 32] { self.owner.business_digest() }
    fn transport_group(&self) -> [u8; 32] { self.owner.transport_group() }
    fn wire_direction(&self) -> nestlink_protocol::network_datagram::Direction { self.owner.wire_direction() }
    fn remaining_lifetime(&self) -> Duration { self.owner.remaining_authorization_lifetime() }
    fn spent_bytes(&self) -> u64 { self.owner.spent_bytes() }
    fn stop(&mut self) { self.owner.stop() }
    fn admit_local(&mut self, packet: &[u8]) -> io::Result<PacketAdmission> { self.owner.admit_local(packet) }
    fn admit_remote(&mut self, packet: &[u8]) -> io::Result<PacketAdmission> { self.owner.admit_remote(packet) }
    fn refresh<'a>(&'a mut self, sdk: &'a Sdk) -> GuardFuture<'a> { Box::pin(async move { self.owner.refresh(sdk, self.local).await.map_err(Into::into) }) }
}
pub(crate) trait WholePacketDevice: Sync {
    fn recv<'a>(&'a self, packet: &'a mut [u8]) -> PacketIoFuture<'a>;
    fn send<'a>(&'a self, packet: &'a [u8]) -> PacketIoFuture<'a>;
}
pub(crate) trait OwnerGuard: Sync {
    /// Cheap original login, maintenance and local intent checks, every 250ms.
    fn check_local(&self) -> Result;
    /// Exact OS/receipt identity observation, every one second.
    fn check(&self) -> GuardFuture<'_>;
}

/// Read an explicitly selected ordinary owner's bounded public plan from one
/// retained descriptor. Parsing/authentication of the captured UID remains the
/// caller's responsibility; this never promotes an untrusted parent to root.
#[cfg(target_os = "linux")]
pub(crate) fn read_public_plan(path: &std::path::Path, maximum: u64) -> Result<(Vec<u8>, u32)> {
    use std::{
        fs::OpenOptions,
        io::Read,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
    };
    if !path.is_absolute() || maximum == 0 || maximum > 65_536 {
        return Err(io::Error::other("bounded absolute public packet plan required").into());
    }
    // NONBLOCK prevents a raced FIFO from stalling the helper watchdog;
    // NOFOLLOW rejects a raced final symlink before any read occurs.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.mode() & 0o077 != 0 || metadata.len() > maximum {
        return Err(
            io::Error::other("bounded owner-private regular public packet plan required").into(),
        );
    }
    let mut bytes = Vec::new();
    (&file).take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(io::Error::other("public packet plan exceeds its bound").into());
    }
    let after = file.metadata()?;
    if metadata.uid() != after.uid()
        || metadata.mode() != after.mode()
        || metadata.len() != after.len()
        || metadata.len() != bytes.len() as u64
        || metadata.mtime() != after.mtime()
        || metadata.mtime_nsec() != after.mtime_nsec()
        || metadata.ctime() != after.ctime()
        || metadata.ctime_nsec() != after.ctime_nsec()
    {
        return Err(io::Error::other(
            "public packet plan changed while reading its original descriptor",
        )
        .into());
    }
    Ok((bytes, metadata.uid()))
}
pub(crate) async fn establish<G: OwnerGuard + ?Sized, A: PacketAuthority + ?Sized>(
    endpoint: &mut DirectPacketEndpoint,
    dial: Option<SocketAddr>,
    sdk: &Sdk,
    access: &mut A,
    guard: &G,
) -> Result {
    let binding = access.business_digest();
    let group = access.transport_group();
    let deadline = Instant::now() + access.remaining_lifetime().min(Duration::from_secs(10));
    let signal = crate::space_dns_system::termination();
    tokio::pin!(signal);
    let connection = endpoint.establish(dial, binding, group, deadline);
    tokio::pin!(connection);
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {biased;
            result=&mut signal=>{result?;return Err(io::Error::other("original packet owner stopped during physical peer proof").into());},
            _=tick.tick()=>{guard.check_local()?;access.refresh(sdk).await?;guard.check().await?;},
            result=&mut connection=>return result,
        }
    }
}
#[derive(Default, Serialize)]
struct Counters {
    sent_packets: u64,
    received_packets: u64,
    rejected_packets: u64,
    spent_bytes: u64,
}
pub(crate) async fn packet_loop<D: WholePacketDevice + ?Sized, G: OwnerGuard + ?Sized, A: PacketAuthority + ?Sized>(
    device: &D,
    endpoint: &mut DirectPacketEndpoint,
    sdk: &Sdk,
    access: &mut A,
    guard: &G,
) -> Result {
    // Full provider-size reads prevent truncation disguising an oversized IP
    // packet as an approved prefix. Only the existing codec fragments the
    // authenticated carrier; the policy boundary remains complete IP packets.
    let mut buffer = vec![0_u8; 65_536];
    let mut assembler = PacketAssembler::new(
        access.business_digest(),
        access.wire_direction().reverse(),
        PACKET_MTU,
    )?;
    let connection = endpoint.connection()?.clone();
    let mut sequence = 0_u64;
    let mut counters = Counters::default();
    let signal = crate::space_dns_system::termination();
    tokio::pin!(signal);
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut refreshed = Instant::now();
    let outcome = loop {
        tokio::select! {biased;
            result=&mut signal=>break result.map_err(Into::into),
            _=tick.tick()=>{
                if let Err(error)=guard.check_local(){break Err(error);}
                if refreshed.elapsed()>=Duration::from_secs(1){
                    if let Err(error)=access.refresh(sdk).await{break Err(error);}
                    if let Err(error)=endpoint.validate_underlay(){break Err(error.into());}
                    if let Err(error)=guard.check().await{break Err(error);}
                    refreshed=Instant::now();
                }
            },
            result=connection.read_datagram()=>{
                let bytes=match result{Ok(bytes)=>bytes,Err(error)=>break Err(error.into())};
                let packet=match assembler.insert(&bytes,std::time::Instant::now()){Ok(Some(packet))=>packet,Ok(None)=>continue,Err(error)=>break Err(error.into())};
                if access.admit_remote(&packet).is_err(){counters.rejected_packets=counters.rejected_packets.saturating_add(1);continue;}
                match tokio::time::timeout(Duration::from_millis(250),device.send(&packet)).await {
                    Ok(Ok(written)) if written==packet.len()=>counters.received_packets=counters.received_packets.saturating_add(1),
                    Ok(Err(error))=>break Err(error.into()),
                    _=>break Err(io::Error::other("complete packet injection did not finish within its bound").into()),
                }
            },
            result=device.recv(&mut buffer)=>{
                let count=match result{Ok(count) if count>0 && count<=buffer.len()=>count,Ok(_)=>break Err(io::Error::other("owned whole-packet device ended or returned an impossible length").into()),Err(error)=>break Err(error.into())};
                if count>PACKET_MTU || access.admit_local(&buffer[..count]).is_err(){counters.rejected_packets=counters.rejected_packets.saturating_add(1);continue;}
                sequence=match sequence.checked_add(1){Some(value)=>value,None=>break Err(io::Error::other("raw packet sequence exhausted").into())};
                let fragments=match encode_direct(access.business_digest(),access.wire_direction(),sequence,&buffer[..count]){Ok(fragments)=>fragments,Err(error)=>break Err(error.into())};
                let mut failed=None;for fragment in fragments{if let Err(error)=connection.send_datagram(fragment.into()){failed=Some(error);break;}}
                if let Some(error)=failed{break Err(error.into());}
                counters.sent_packets=counters.sent_packets.saturating_add(1);
            },
        }
    };
    counters.spent_bytes = access.spent_bytes();
    // Aggregate counts only: no packet/address/grant/key/application contents.
    println!(
        "Packet owner counters: {}",
        serde_json::to_string(&counters)?
    );
    outcome
}
