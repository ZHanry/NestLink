//! QUIC with pinned mutual TLS; no 0-RTT or implicit legacy protocol fallback.
use nestlink_identity::InstallationIdentity;
use nestlink_protocol::QUIC_DATAGRAM_BYTES;
use nestlink_transport_stream::tls;
pub mod discovery;
pub mod node;
pub mod service;
mod virtual_udp;
use quinn::{
    ClientConfig, Connection, Endpoint, ServerConfig, TransportConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn transport() -> Arc<TransportConfig> {
    Arc::new(transport_value())
}
fn transport_value() -> TransportConfig {
    let mut value = TransportConfig::default();
    value.max_concurrent_bidi_streams(16_u8.into());
    value.max_concurrent_uni_streams(8_u8.into());
    value.stream_receive_window(2_097_152_u32.into());
    value.receive_window(16_777_216_u32.into());
    value.datagram_receive_buffer_size(Some(32 * QUIC_DATAGRAM_BYTES as usize));
    value.datagram_send_buffer_size(16 * QUIC_DATAGRAM_BYTES as usize);
    value.keep_alive_interval(Some(Duration::from_secs(3)));
    value
}
pub fn listener(
    address: SocketAddr,
    identity: &InstallationIdentity,
    expected_peer_fingerprint: [u8; 32],
) -> Result<Endpoint> {
    let crypto =
        QuicServerConfig::try_from(tls::server_config(identity, expected_peer_fingerprint)?)?;
    let mut config = ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(transport());
    Ok(Endpoint::server(config, address)?)
}
pub fn connector(
    address: SocketAddr,
    identity: &InstallationIdentity,
    expected_peer_fingerprint: [u8; 32],
) -> Result<Endpoint> {
    let mut endpoint = Endpoint::client(address)?;
    let crypto =
        QuicClientConfig::try_from(tls::client_config(identity, expected_peer_fingerprint)?)?;
    let mut config = ClientConfig::new(Arc::new(crypto));
    config.transport_config(transport());
    endpoint.set_default_client_config(config);
    Ok(endpoint)
}
pub async fn connect(
    endpoint: &Endpoint,
    address: SocketAddr,
    budget: Duration,
) -> Result<Connection> {
    let connecting = endpoint.connect(address, "peer.nestlink.invalid")?;
    Ok(tokio::time::timeout(budget, connecting).await??)
}

/// Bidirectional endpoint; STUN and QUIC consume the very same UDP socket.
pub fn discovery_endpoint(
    address: SocketAddr,
    identity: &InstallationIdentity,
    expected_peer_fingerprint: [u8; 32],
    trusted_stun_servers: Vec<SocketAddr>,
) -> Result<(Endpoint, Arc<discovery::DiscoverySocket>)> {
    use quinn::Runtime;
    let runtime = Arc::new(quinn::TokioRuntime);
    let socket = runtime.wrap_udp_socket(bind_discovery_socket(address)?)?;
    let socket = Arc::new(discovery::DiscoverySocket::new(
        socket,
        trusted_stun_servers,
    )?);
    let crypto =
        QuicServerConfig::try_from(tls::server_config(identity, expected_peer_fingerprint)?)?;
    let mut server = ServerConfig::with_crypto(Arc::new(crypto));
    server.transport_config(transport());
    let mut endpoint = Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server),
        socket.clone(),
        runtime,
    )?;
    let crypto =
        QuicClientConfig::try_from(tls::client_config(identity, expected_peer_fingerprint)?)?;
    let mut client = ClientConfig::new(Arc::new(crypto));
    client.transport_config(transport());
    endpoint.set_default_client_config(client);
    Ok((endpoint, socket))
}

fn bind_discovery_socket(address: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    let domain = if address.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    if address.is_ipv6() {
        // Each family has its own candidate/QUIC socket. Never permit an
        // IPv4-mapped source to bypass IPv4 private-address policy on IPv6.
        socket.set_only_v6(true)?;
    }
    socket.bind(&address.into())?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

#[cfg(test)]
mod bind_tests {
    use super::*;

    #[test]
    fn ipv6_discovery_socket_is_ipv6_only() -> std::io::Result<()> {
        let socket = bind_discovery_socket(SocketAddr::from(([0_u16; 8], 0)))?;
        assert!(socket2::SockRef::from(&socket).only_v6()?);
        assert!(socket.local_addr()?.is_ipv6());
        Ok(())
    }
}
