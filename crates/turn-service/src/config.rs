use rustls::ServerConfig as TlsServerConfig;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

/// One IPv4 or IPv6 UDP relay range. The advertised address may differ from
/// `bind_ip` for nodes behind a static one-to-one NAT.
#[derive(Clone, Debug)]
pub struct RelayPortPool {
    pub bind_ip: IpAddr,
    pub public_ip: IpAddr,
    pub min_port: u16,
    pub max_port: u16,
}

impl RelayPortPool {
    fn validate(&self) -> Result<(), TurnServiceError> {
        if self.min_port == 0
            || self.max_port < self.min_port
            || self.public_ip.is_unspecified()
            || self.public_ip.is_multicast()
            || self.bind_ip.is_multicast()
            || self.bind_ip.is_ipv4() != self.public_ip.is_ipv4()
        {
            return Err(TurnServiceError::Configuration);
        }
        Ok(())
    }
}

/// Listener addresses are independent so deployments can keep Caddy on the
/// primary 443/TCP address and give TURN/TLS a separate IP or node.
#[derive(Clone)]
pub struct TurnServiceConfig {
    pub realm: String,
    pub udp_bind: Option<SocketAddr>,
    pub tcp_bind: Option<SocketAddr>,
    pub tls_bind: Option<SocketAddr>,
    pub tls_server_config: Option<Arc<TlsServerConfig>>,
    pub relay_port_pools: Vec<RelayPortPool>,
    pub max_connections: usize,
}

impl TurnServiceConfig {
    pub fn validate(&self) -> Result<(), TurnServiceError> {
        let has_listener =
            self.udp_bind.is_some() || self.tcp_bind.is_some() || self.tls_bind.is_some();
        if !has_listener
            || self.realm.is_empty()
            || self.realm.len() > 128
            || !self.realm.is_ascii()
            || self.realm.bytes().any(|byte| byte.is_ascii_control())
            || self.relay_port_pools.is_empty()
            || self.max_connections == 0
            || self.max_connections > 16_384
            || self.tls_bind.is_some() != self.tls_server_config.is_some()
        {
            return Err(TurnServiceError::Configuration);
        }
        for pool in &self.relay_port_pools {
            pool.validate()?;
        }
        for (index, pool) in self.relay_port_pools.iter().enumerate() {
            let overlaps = self.relay_port_pools[..index].iter().any(|previous| {
                previous.bind_ip == pool.bind_ip
                    && previous.min_port <= pool.max_port
                    && pool.min_port <= previous.max_port
            });
            if overlaps {
                return Err(TurnServiceError::Configuration);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TurnListenAddresses {
    pub udp: Option<SocketAddr>,
    pub tcp: Option<SocketAddr>,
    pub tls: Option<SocketAddr>,
}

#[derive(Debug, thiserror::Error)]
pub enum TurnServiceError {
    #[error("invalid managed TURN service configuration")]
    Configuration,
    #[error("node authorization is no longer online")]
    Offline,
    #[error("TURN bind failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("TURN allocation server failed: {0}")]
    Turn(#[from] turn::Error),
    #[error("TURN authorization failed: {0}")]
    Authorization(#[from] nestlink_traversal::turn::TurnGrantError),
    #[error("TURN server command failed")]
    ServerCommand,
}
