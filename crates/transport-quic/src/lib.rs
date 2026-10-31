//! QUIC with pinned mutual TLS; no 0-RTT or implicit legacy protocol fallback.
use nestlink_identity::InstallationIdentity;
use nestlink_protocol::QUIC_DATAGRAM_BYTES;
use nestlink_transport_stream::tls;
pub mod discovery;
mod fragments;
pub mod packet_codec;
pub mod node;
pub mod routed;
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
    // Bound application buffering so video backpressure reaches its deadline
    // and adaptive producer. Input/feedback retain their higher stream priority.
    value.send_window(512 * 1024);
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
    let path = nestlink_platform_network::path::NetworkPathManager::from_default()?;
    let socket = runtime.wrap_udp_socket(path.bind_udp(address)?)?;
    let socket = Arc::new(discovery::DiscoverySocket::on_path(
        socket,
        trusted_stun_servers,
        path,
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

#[cfg(test)]
fn bind_discovery_socket(address: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    nestlink_platform_network::path::NetworkPathManager::from_default()?.bind_udp(address)
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
