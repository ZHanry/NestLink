//! Explicit single-port PCP adaptation. The mature component owns the protocol;
//! this object retains the nonce before any request, including canceled creates.
use crab_nat::{
    InternetProtocol, PortMapping, PortMappingOptions, PortMappingType, TimeoutConfig,
    pcp::{self, BaseMapRequest, DropMappingRange},
};
use rand_core::{OsRng, RngCore};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroU16,
    time::{Duration, Instant},
};

const MAX_LIFETIME_SECONDS: u64 = 120;
const REQUEST_BUDGET: Duration = Duration::from_secs(1);
const TIMEOUT: TimeoutConfig = TimeoutConfig {
    initial_timeout: Duration::from_millis(200),
    max_retries: 1,
    max_retry_timeout: Some(Duration::from_millis(400)),
};

fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "PCP mapping unavailable or changed",
    )
}

/// One exact UDP port on one explicitly approved gateway. This is not a socket
/// owner: its caller must retain the original bound business socket until close.
/// Dropping this value provides no gateway cleanup receipt; call release().
pub struct PcpMapping {
    gateway: Ipv4Addr,
    local: SocketAddr,
    port: NonZeroU16,
    nonce: pcp::Nonce,
    authorization_deadline: Instant,
    attempted: bool,
    stopped: bool,
    expected: Option<SocketAddr>,
    mapping: Option<PortMapping>,
    gateway_epoch: Option<u32>,
}

impl PcpMapping {
    pub fn new(
        gateway: Ipv4Addr,
        local: SocketAddr,
        authorization_deadline: Instant,
    ) -> io::Result<Self> {
        if !gateway.is_private()
            || !matches!(local.ip(), IpAddr::V4(ip) if ip.is_private())
            || local.ip() == IpAddr::V4(gateway)
            || authorization_deadline <= Instant::now() + Duration::from_secs(3)
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let port = NonZeroU16::new(local.port()).ok_or(io::ErrorKind::InvalidInput)?;
        let mut bytes = [0_u8; 12];
        OsRng.fill_bytes(&mut bytes);
        let nonce = [
            u32::from_ne_bytes(bytes[0..4].try_into().map_err(|_| refused())?),
            u32::from_ne_bytes(bytes[4..8].try_into().map_err(|_| refused())?),
            u32::from_ne_bytes(bytes[8..12].try_into().map_err(|_| refused())?),
        ];
        Ok(Self {
            gateway,
            local,
            port,
            nonce,
            authorization_deadline,
            attempted: false,
            stopped: false,
            expected: None,
            mapping: None,
            gateway_epoch: None,
        })
    }

    /// Reuse the same nonce and original authorization deadline for renewal.
    /// The caller retains this object when this future is canceled. A request
    /// may have reached the gateway even when no response reached this process.
    pub async fn establish_or_renew(&mut self) -> io::Result<SocketAddr> {
        if self.stopped {
            return Err(refused());
        }
        // Cancellation or any unsuccessful request makes this owner terminal.
        // Cleanup remains possible, but the same object cannot retry/revive it.
        self.stopped = true;
        if self
            .mapping
            .as_ref()
            .is_some_and(|mapping| Instant::now() >= mapping.expiration())
        {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let lifetime = self
            .authorization_deadline
            .saturating_duration_since(Instant::now())
            .as_secs()
            .saturating_sub(1)
            .min(MAX_LIFETIME_SECONDS);
        if lifetime < 2 {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let lifetime = u32::try_from(lifetime).map_err(|_| refused())?;
        let suggested_ip = self.expected.map(|address| address.ip());
        self.attempted = true;
        let mapping = tokio::time::timeout(
            REQUEST_BUDGET,
            pcp::port_mapping(
                BaseMapRequest::new(
                    self.gateway.into(),
                    self.local.ip(),
                    InternetProtocol::Udp,
                    self.port,
                ),
                Some(self.nonce),
                suggested_ip,
                PortMappingOptions {
                    external_port: Some(self.port),
                    lifetime_seconds: Some(lifetime),
                    timeout_config: Some(TIMEOUT),
                },
            ),
        )
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
        .map_err(|_| refused())?;
        let external_ip = match mapping.mapping_type() {
            PortMappingType::Pcp { external_ip, .. } => external_ip,
            PortMappingType::NatPmp => return Err(refused()),
        };
        let external = SocketAddr::new(external_ip, mapping.external_port().get());
        // Keep the returned lease even when rejected: release still addresses
        // the exact retained nonce. No changed tuple may reach signed signaling.
        self.mapping = Some(mapping);
        let mapping = self.mapping.as_ref().ok_or_else(refused)?;
        if !external.is_ipv4()
            || mapping.external_port() != self.port
            || mapping.lifetime() < 2
            || mapping.lifetime() > lifetime
            || mapping.expiration() > self.authorization_deadline
            || self.expected.is_some_and(|expected| expected != external)
            || self
                .gateway_epoch
                .is_some_and(|epoch| mapping.gateway_epoch() < epoch)
        {
            return Err(refused());
        }
        self.expected = Some(external);
        self.gateway_epoch = Some(mapping.gateway_epoch());
        self.stopped = false;
        Ok(external)
    }

    /// The existing session owner must stop or renew before this deadline.
    pub fn renewal_deadline(&self) -> io::Result<Instant> {
        let mapping = self.mapping.as_ref().ok_or_else(refused)?;
        if self.stopped
            || !self.attempted
            || Instant::now() >= mapping.expiration()
            || Instant::now() >= self.authorization_deadline
        {
            return Err(io::ErrorKind::TimedOut.into());
        }
        Ok(
            (mapping.expiration() - Duration::from_secs(u64::from(mapping.lifetime()) / 2))
                .min(self.authorization_deadline),
        )
    }

    /// Delete only this nonce, client address, protocol and nonzero local port.
    /// In particular, the component's all-ports deletion API is never used.
    /// A failed/canceled create is cleaned with the same exact request scope.
    pub async fn release(&mut self) -> io::Result<()> {
        self.stopped = true;
        if !self.attempted {
            return Ok(());
        }
        tokio::time::timeout(
            REQUEST_BUDGET,
            pcp::try_drop_mapping(
                self.gateway.into(),
                self.local.ip(),
                self.nonce,
                DropMappingRange::Single {
                    protocol: InternetProtocol::Udp,
                    internal_port: self.port,
                },
                Some(TIMEOUT),
            ),
        )
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
        .map_err(|_| refused())?;
        self.attempted = false;
        self.mapping = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
