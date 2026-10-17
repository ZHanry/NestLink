use crate::{RelayPortPool, TurnServiceError};
use async_trait::async_trait;
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::net::UdpSocket;
use turn::{Error, relay::RelayAddressGenerator};
use webrtc_util::Conn;

#[derive(Clone)]
struct PoolCursor {
    pool: RelayPortPool,
    next: Arc<AtomicUsize>,
}

#[derive(Clone)]
pub(crate) struct RelayPortGenerator {
    pools: Vec<PoolCursor>,
}

impl RelayPortGenerator {
    pub(crate) fn new(pools: &[RelayPortPool]) -> Result<Self, TurnServiceError> {
        if pools.is_empty() {
            return Err(TurnServiceError::Configuration);
        }
        Ok(Self {
            pools: pools
                .iter()
                .cloned()
                .map(|pool| PoolCursor {
                    pool,
                    next: Arc::new(AtomicUsize::new(0)),
                })
                .collect(),
        })
    }

    async fn bind_from_pool(
        pool: &PoolCursor,
        requested_port: u16,
    ) -> Result<(Arc<dyn Conn + Send + Sync>, SocketAddr), Error> {
        let count = usize::from(pool.pool.max_port - pool.pool.min_port) + 1;
        if requested_port != 0 {
            if requested_port < pool.pool.min_port || requested_port > pool.pool.max_port {
                return Err(Error::ErrMaxRetriesExceeded);
            }
            return Self::bind(pool, requested_port).await;
        }

        let start = pool.next.fetch_add(1, Ordering::Relaxed) % count;
        for offset in 0..count {
            let port = pool.pool.min_port + ((start + offset) % count) as u16;
            if let Ok(result) = Self::bind(pool, port).await {
                return Ok(result);
            }
        }
        Err(Error::ErrMaxRetriesExceeded)
    }

    async fn bind(
        pool: &PoolCursor,
        port: u16,
    ) -> Result<(Arc<dyn Conn + Send + Sync>, SocketAddr), Error> {
        let socket = Arc::new(UdpSocket::bind(SocketAddr::new(pool.pool.bind_ip, port)).await?);
        let bound = socket.local_addr()?;
        let relay_addr = SocketAddr::new(pool.pool.public_ip, bound.port());
        Ok((socket, relay_addr))
    }
}

#[async_trait]
impl RelayAddressGenerator for RelayPortGenerator {
    fn validate(&self) -> Result<(), Error> {
        if self.pools.is_empty()
            || self.pools.iter().any(|pool| {
                pool.pool.min_port == 0
                    || pool.pool.max_port < pool.pool.min_port
                    || pool.pool.bind_ip.is_ipv4() != pool.pool.public_ip.is_ipv4()
            })
        {
            return Err(Error::ErrListeningAddressInvalid);
        }
        Ok(())
    }

    async fn allocate_conn(
        &self,
        use_ipv4: bool,
        requested_port: u16,
    ) -> Result<(Arc<dyn Conn + Send + Sync>, SocketAddr), Error> {
        for pool in self
            .pools
            .iter()
            .filter(|pool| pool.pool.bind_ip.is_ipv4() == use_ipv4)
        {
            if let Ok(result) = Self::bind_from_pool(pool, requested_port).await {
                return Ok(result);
            }
        }
        Err(Error::ErrMaxRetriesExceeded)
    }
}
