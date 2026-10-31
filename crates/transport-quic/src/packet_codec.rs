//! Narrow reuse of the existing NRD1 codec and bounded fragment owner for a
//! direct raw-IP business carrier. This framing grants no packet authority.
use crate::fragments::{Fragment, Reassembly};
mod runtime;
use nestlink_protocol::network_datagram as wire;
use std::{
    io,
    time::{Duration, Instant},
};

pub const ALPN: &[u8] = b"nestlink/network-packet/1";

// Keep the connection private until both grant/path proofs complete. Closing
// on drop also covers cancellation of the establishing future by its owner.
struct PendingConnection(Option<quinn::Connection>);
impl Drop for PendingConnection {
    fn drop(&mut self) {
        if let Some(connection) = &self.0 {
            connection.close(1u32.into(), b"raw packet proof incomplete");
        }
    }
}

/// A single-use physical endpoint pinned to the explicitly chosen underlay
/// interface. It is constructed before creating any managed TUN routes.
pub struct DirectPacketEndpoint {
    endpoint: Option<quinn::Endpoint>,
    connection: Option<quinn::Connection>,
    released: Option<tokio::sync::oneshot::Receiver<()>>,
    runtime: std::sync::Arc<runtime::PacketRuntime>,
    path: nestlink_platform_network::path::NetworkPathManager,
    address: std::net::SocketAddr,
    expected_peer: nestlink_protocol::network::PeerId,
    attempted: bool,
    close_deadline: Option<tokio::time::Instant>,
}
impl DirectPacketEndpoint {
    pub fn bind(
        address: std::net::SocketAddr,
        identity: &nestlink_identity::InstallationIdentity,
        expected_peer: nestlink_protocol::network::PeerId,
        path: nestlink_platform_network::path::NetworkPathManager,
    ) -> crate::Result<Self> {
        use quinn::{
            Runtime,
            crypto::rustls::{QuicClientConfig, QuicServerConfig},
        };
        use std::sync::Arc;
        if path.selected.is_none() || identity.fingerprint() == expected_peer.0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "raw IP requires an explicit underlay interface and a distinct pinned peer",
            )
            .into());
        }
        let mut transport = crate::transport_value();
        transport.max_concurrent_bidi_streams(1u8.into());
        transport.max_concurrent_uni_streams(0u8.into());
        transport.initial_mtu(1200);
        transport.min_mtu(1200);
        transport.mtu_discovery_config(None);
        let transport = Arc::new(transport);
        let mut server_tls =
            nestlink_transport_stream::tls::server_config(identity, expected_peer.0)?;
        server_tls.alpn_protocols = vec![ALPN.to_vec()];
        let mut server =
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_tls)?));
        server.transport_config(transport.clone());
        server.migration(false);
        let mut client_tls =
            nestlink_transport_stream::tls::client_config(identity, expected_peer.0)?;
        client_tls.alpn_protocols = vec![ALPN.to_vec()];
        let mut client =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_tls)?));
        client.transport_config(transport);
        let socket = path.bind_udp(address)?;
        let address = socket.local_addr()?;
        let runtime = Arc::new(runtime::PacketRuntime::new());
        let inner = runtime.wrap_udp_socket(socket)?;
        let (socket, released) = crate::service::socket::tracked(inner);
        let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server),
            socket,
            runtime.clone(),
        )?;
        endpoint.set_default_client_config(client);
        Ok(Self {
            endpoint: Some(endpoint),
            connection: None,
            released: Some(released),
            runtime,
            path,
            address,
            expected_peer,
            attempted: false,
            close_deadline: None,
        })
    }
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.address
    }
    pub fn validate_underlay(&self) -> io::Result<()> {
        self.path.validate_bound(self.address)
    }
    fn endpoint(&self) -> io::Result<&quinn::Endpoint> {
        self.endpoint
            .as_ref()
            .ok_or_else(|| io::ErrorKind::NotConnected.into())
    }
    pub fn connection(&self) -> io::Result<&quinn::Connection> {
        self.connection
            .as_ref()
            .ok_or_else(|| io::ErrorKind::NotConnected.into())
    }
    /// Both peers prove the original access digest and path transport group
    /// inside pinned TLS before exposing a datagram to the IP admission owner.
    pub async fn establish(
        &mut self,
        destination: Option<std::net::SocketAddr>,
        business_digest: [u8; 32],
        transport_group: [u8; 32],
        deadline: tokio::time::Instant,
    ) -> crate::Result<()> {
        if self.attempted
            || self.close_deadline.is_some()
            || business_digest == [0; 32]
            || transport_group == [0; 32]
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "raw packet carrier is single-use and needs exact verified bindings",
            )
            .into());
        }
        self.attempted = true;
        self.validate_underlay()?;
        let connection = if let Some(destination) = destination {
            tokio::time::timeout_at(
                deadline,
                self.endpoint()?
                    .connect(destination, "peer.nestlink.invalid")?,
            )
            .await??
        } else {
            let incoming = tokio::time::timeout_at(deadline, self.endpoint()?.accept())
                .await?
                .ok_or_else(|| io::Error::from(io::ErrorKind::ConnectionAborted))?;
            tokio::time::timeout_at(deadline, incoming).await??
        };
        let mut pending = PendingConnection(Some(connection));
        let connection = pending
            .0
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?;
        if crate::routed::authenticated_peer_fingerprint(connection)? != self.expected_peer.0 {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied).into());
        }
        let mut binding = [0; 64];
        binding[..32].copy_from_slice(&business_digest);
        binding[32..].copy_from_slice(&transport_group);
        tokio::time::timeout_at(deadline, async {
            let (mut send, mut receive) = if destination.is_some() {
                connection.open_bi().await?
            } else {
                connection.accept_bi().await?
            };
            send.write_all(&binding).await?;
            send.finish()?;
            let received = receive.read_to_end(64).await?;
            if received.as_slice() != binding
                || connection
                    .max_datagram_size()
                    .is_none_or(|size| size < wire::HEADER + wire::FRAGMENT_BYTES)
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "raw packet grant/path proof or carrier MTU mismatch",
                )
                .into());
            }
            self.validate_underlay()?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        })
        .await??;
        self.connection = pending.0.take();
        Ok(())
    }
    pub fn request_close(&self) {
        if let Some(connection) = &self.connection {
            connection.close(0u32.into(), b"raw packet business stopping");
        }
        if let Some(endpoint) = &self.endpoint {
            endpoint.close(0u32.into(), b"raw packet endpoint stopping");
        }
    }
    pub async fn close_and_wait(&mut self, deadline: tokio::time::Instant) -> io::Result<()> {
        let deadline = *self.close_deadline.get_or_insert(deadline);
        self.request_close();
        self.connection = None;
        self.endpoint = None;
        if let Some(mut tasks) = self.runtime.stop() {
            tokio::time::timeout_at(deadline, async {
                while let Some(result) = tasks.join_next().await {
                    if let Err(error) = result {
                        if !error.is_cancelled() {
                            return Err(io::Error::other(error));
                        }
                    }
                }
                Ok(())
            })
            .await
            .map_err(|_| io::ErrorKind::TimedOut)??;
        }
        if let Some(released) = self.released.as_mut() {
            tokio::time::timeout_at(deadline, released)
                .await
                .map_err(|_| io::ErrorKind::TimedOut)?
                .map_err(|_| {
                    io::Error::other("raw packet physical UDP release was not confirmed")
                })?;
            self.released = None;
        }
        Ok(())
    }
}
impl Drop for DirectPacketEndpoint {
    fn drop(&mut self) {
        self.request_close();
        drop(self.runtime.stop());
    }
}

/// Encodes the existing bounded carrier fragments and consumes the hop locally
/// because a direct endpoint path has no forwarding node. The dedicated raw-IP
/// ALPN keeps these envelopes separate from the routed adjacency protocol.
pub fn encode_direct(
    binding: [u8; 32],
    direction: wire::Direction,
    sequence: u64,
    packet: &[u8],
) -> io::Result<Vec<Vec<u8>>> {
    let mut fragments =
        wire::encode(binding, direction, sequence, packet).map_err(io::Error::other)?;
    for fragment in &mut fragments {
        wire::forward(fragment, binding, direction).map_err(io::Error::other)?;
    }
    Ok(fragments)
}

pub struct PacketAssembler {
    binding: [u8; 32],
    direction: wire::Direction,
    maximum: usize,
    assembly: Reassembly,
}
impl PacketAssembler {
    pub fn new(binding: [u8; 32], direction: wire::Direction, maximum: usize) -> io::Result<Self> {
        if binding == [0; 32] || maximum == 0 || maximum > wire::PACKET_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid raw packet assembly binding or byte bound",
            ));
        }
        Ok(Self {
            binding,
            direction,
            maximum,
            assembly: Reassembly::new(
                wire::FRAGMENT_BYTES,
                wire::PENDING_PACKETS,
                wire::REPLAY_WINDOW,
                Duration::from_millis(wire::PACKET_AGE_MS),
            ),
        })
    }
    pub fn insert(&mut self, bytes: &[u8], now: Instant) -> io::Result<Option<Vec<u8>>> {
        let fragment = wire::decode(bytes).map_err(io::Error::other)?;
        if fragment.binding != self.binding
            || fragment.direction != self.direction
            || fragment.remaining_hops != 0
            || fragment.length > self.maximum
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "raw packet carrier binding, direction or hop mismatch",
            ));
        }
        Ok(self
            .assembly
            .insert(
                Fragment {
                    packet: fragment.packet,
                    length: fragment.length,
                    index: fragment.index,
                    payload: fragment.payload,
                },
                now,
            )?
            .map(|packet| packet.bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn endpoints() -> crate::Result<(DirectPacketEndpoint, DirectPacketEndpoint)> {
        use nestlink_platform_network::path::{NetworkPathManager, RoutePolicy};
        let interface = NetworkPathManager::interfaces()?
            .into_iter()
            .find(|interface| {
                interface.up
                    && interface
                        .addresses
                        .iter()
                        .any(|ip| ip.is_ipv4() && !ip.is_loopback() && !ip.is_unspecified())
            })
            .ok_or_else(|| {
                io::Error::other("hosted packet fixture needs an active IPv4 interface")
            })?;
        let address = interface
            .addresses
            .iter()
            .copied()
            .find(|ip| ip.is_ipv4() && !ip.is_loopback() && !ip.is_unspecified())
            .ok_or_else(|| io::Error::other("hosted packet fixture source missing"))?;
        let path = NetworkPathManager::new(RoutePolicy::Interface(interface.index))?;
        let first = nestlink_identity::InstallationIdentity::generate();
        let second = nestlink_identity::InstallationIdentity::generate();
        Ok((
            DirectPacketEndpoint::bind(
                (address, 0).into(),
                &first,
                nestlink_protocol::network::PeerId(second.fingerprint()),
                path.clone(),
            )?,
            DirectPacketEndpoint::bind(
                (address, 0).into(),
                &second,
                nestlink_protocol::network::PeerId(first.fingerprint()),
                path,
            )?,
        ))
    }
    #[tokio::test]
    async fn exact_mutual_proof_exposes_only_the_authenticated_datagram_connection()
    -> crate::Result<()> {
        let (mut first, mut second) = endpoints()?;
        let destination = second.local_addr();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let (left, right) = tokio::join!(
            first.establish(Some(destination), [7; 32], [8; 32], deadline),
            second.establish(None, [7; 32], [8; 32], deadline)
        );
        left?;
        right?;
        first
            .connection()?
            .send_datagram(b"actual packet carrier".to_vec().into())?;
        assert_eq!(
            tokio::time::timeout_at(deadline, second.connection()?.read_datagram())
                .await??
                .as_ref(),
            b"actual packet carrier"
        );
        let cleanup = tokio::time::Instant::now() + Duration::from_secs(5);
        let (left, right) = tokio::join!(
            first.close_and_wait(cleanup),
            second.close_and_wait(cleanup)
        );
        left?;
        right?;
        assert!(first.connection().is_err());
        assert!(second.connection().is_err());
        Ok(())
    }
    #[tokio::test]
    async fn slow_initial_handshake_cannot_extend_terminal_physical_socket_ownership()
    -> crate::Result<()> {
        let (mut first, mut second) = endpoints()?;
        let first_address = first.local_addr();
        let second_address = second.local_addr();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
        let accept = async {
            tokio::time::sleep(Duration::from_secs(6)).await;
            second.establish(None, [7; 32], [8; 32], deadline).await
        };
        let (left, right) = tokio::join!(
            first.establish(Some(second_address), [7; 32], [8; 32], deadline),
            accept
        );
        left?;
        right?;
        first.connection()?.send_datagram(b"after slow proof".to_vec().into())?;
        assert_eq!(tokio::time::timeout_at(deadline, second.connection()?.read_datagram())
            .await??.as_ref(), b"after slow proof");
        let cleanup = tokio::time::Instant::now() + Duration::from_secs(5);
        let (left, right) = tokio::join!(first.close_and_wait(cleanup), second.close_and_wait(cleanup));
        left?;
        right?;
        assert!(first.released.is_none() && second.released.is_none());
        let rebound_first = std::net::UdpSocket::bind(first_address)?;
        let rebound_second = std::net::UdpSocket::bind(second_address)?;
        drop((rebound_first, rebound_second));
        assert!(first.establish(Some(second_address), [7; 32], [8; 32], deadline).await.is_err());
        Ok(())
    }
    #[tokio::test]
    async fn mismatched_mutual_proof_never_exposes_a_datagram_connection() -> crate::Result<()> {
        let (mut first, mut second) = endpoints()?;
        let destination = second.local_addr();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let (left, right) = tokio::join!(
            first.establish(Some(destination), [7; 32], [8; 32], deadline),
            second.establish(None, [9; 32], [8; 32], deadline)
        );
        assert!(left.is_err());
        assert!(right.is_err());
        assert!(first.connection().is_err());
        assert!(second.connection().is_err());
        let cleanup = tokio::time::Instant::now() + Duration::from_secs(5);
        let (left, right) = tokio::join!(
            first.close_and_wait(cleanup),
            second.close_and_wait(cleanup)
        );
        left?;
        right?;
        assert!(first.released.is_none());
        assert!(second.released.is_none());
        Ok(())
    }
    #[tokio::test]
    async fn incomplete_mutual_proof_times_out_without_exposing_or_restarting_connection()
    -> crate::Result<()> {
        let (mut first, mut second) = endpoints()?;
        let destination = second.local_addr();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        let accept = async {
            let incoming = tokio::time::timeout_at(deadline, second.endpoint()?.accept())
                .await?
                .ok_or_else(|| io::Error::from(io::ErrorKind::ConnectionAborted))?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                tokio::time::timeout_at(deadline, incoming).await??,
            )
        };
        let (result, connection) = tokio::join!(
            first.establish(Some(destination), [7; 32], [8; 32], deadline),
            accept
        );
        let connection = connection?;
        assert!(result.is_err());
        assert!(first.connection().is_err());
        assert!(
            first
                .establish(
                    Some(destination),
                    [7; 32],
                    [8; 32],
                    tokio::time::Instant::now() + Duration::from_secs(3)
                )
                .await
                .is_err()
        );
        tokio::time::timeout(Duration::from_secs(3), connection.closed()).await?;
        drop(connection);
        let cleanup = tokio::time::Instant::now() + Duration::from_secs(5);
        let (left, right) = tokio::join!(
            first.close_and_wait(cleanup),
            second.close_and_wait(cleanup)
        );
        left?;
        right?;
        Ok(())
    }
    #[test]
    fn full_ipv6_minimum_mtu_reuses_existing_bounded_assembler_and_replay_window() -> io::Result<()>
    {
        let binding = [7; 32];
        let direction = wire::Direction::FirstToSecond;
        let mut owner = PacketAssembler::new(binding, direction, 1280)?;
        let packet = vec![5; 1280];
        let fragments = encode_direct(binding, direction, 1, &packet)?;
        assert_eq!(fragments.len(), 2);
        let now = Instant::now();
        assert!(owner.insert(&fragments[1], now)?.is_none());
        assert_eq!(owner.insert(&fragments[0], now)?, Some(packet));
        assert!(owner.insert(&fragments[0], now)?.is_none());
        let mut wrong = PacketAssembler::new([8; 32], direction, 1280)?;
        assert!(wrong.insert(&fragments[0], now).is_err());
        let mut wrong = PacketAssembler::new(binding, direction.reverse(), 1280)?;
        assert!(wrong.insert(&fragments[0], now).is_err());
        Ok(())
    }
    #[test]
    fn stale_partial_packet_never_becomes_an_injected_packet() -> io::Result<()> {
        let binding = [7; 32];
        let direction = wire::Direction::FirstToSecond;
        let mut owner = PacketAssembler::new(binding, direction, 1280)?;
        let fragments = encode_direct(binding, direction, 1, &vec![5; 1280])?;
        let now = Instant::now();
        assert!(owner.insert(&fragments[0], now)?.is_none());
        assert!(
            owner
                .insert(
                    &fragments[1],
                    now + Duration::from_millis(wire::PACKET_AGE_MS)
                )?
                .is_none()
        );
        Ok(())
    }
}
