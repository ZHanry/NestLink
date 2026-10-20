//! An explicit, read-only STUN probe through the same production socket factory.
//! Does not claim that a STUN result qualifies an Internet peer/media path.
use nestlink_platform_network::path::{NetworkPathManager, RoutePolicy};
use nestlink_traversal::stun;
use std::{
    io,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: media-route-probe system|physical|<index> <STUN IP:port>".into());
    }
    let policy = match args[0].as_str() {
        "system" => RoutePolicy::System,
        "physical" => RoutePolicy::PreferPhysical,
        value => RoutePolicy::Interface(value.parse()?),
    };
    let server: SocketAddr = args[1].parse()?;
    let manager = NetworkPathManager::new(policy)?;
    let local: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse()?;
    let socket = tokio::net::UdpSocket::from_std(manager.bind_udp(local)?)?;
    let mut observed = Vec::new();
    let mut durations = Vec::new();
    for _ in 0..2 {
        let transaction = stun::transaction();
        let started = Instant::now();
        socket.send_to(&stun::request(&transaction), server).await?;
        let mapping = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let mut buffer = [0; stun::MAXIMUM];
                let (length, from) = socket.recv_from(&mut buffer).await?;
                if from == server
                    && let Ok(mapping) = stun::mapped_address(&buffer[..length], &transaction)
                {
                    return Ok::<_, io::Error>(mapping);
                }
            }
        })
        .await??;
        observed.push(mapping);
        durations.push(started.elapsed().as_millis());
    }
    let redact = |address: IpAddr| match address {
        IpAddr::V4(address) => format!("{}.***.***.***", address.octets()[0]),
        IpAddr::V6(_) => "IPv6 (redacted)".into(),
    };
    println!(
        "{}",
        serde_json::json!({
            "policy": format!("{policy:?}"), "interface_index": manager.selected.as_ref().map(|value| value.index),
            "physical": manager.selected.as_ref().map(|value| value.physical),
            "configured_default_route": manager.selected.as_ref().map(|value| value.default_route),
            "discovery_ms": durations, "mapping": redact(observed[0].ip()),
            "same_socket_mapping_stable": observed[0] == observed[1],
            "peer_media_qualified": false,
        })
    );
    Ok(())
}
