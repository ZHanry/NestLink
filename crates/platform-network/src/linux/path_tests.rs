//! Actual kernel interfaces and pinned sockets inside an owned test netns.
use crate::path::{NetworkInterface, NetworkPathManager, RoutePolicy};
use std::{
    io,
    net::{IpAddr, SocketAddr},
    process::Command,
    time::Duration,
};

fn ip(arguments: &[&str]) -> io::Result<()> {
    let status = Command::new("ip").args(arguments).status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "isolated ip operation failed: {arguments:?}"
        )));
    }
    Ok(())
}

fn interface(name: &str) -> io::Result<NetworkInterface> {
    NetworkPathManager::interfaces()?
        .into_iter()
        .find(|interface| interface.name == name)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("isolated interface missing: {name}"),
            )
        })
}

fn assert_pinned(socket: &std::net::UdpSocket, index: u32) -> io::Result<()> {
    let socket = socket2::SockRef::from(socket);
    let actual = if socket
        .local_addr()?
        .as_socket()
        .is_some_and(|address| address.is_ipv6())
    {
        assert!(socket.only_v6()?);
        socket.device_index_v6()?
    } else {
        socket.device_index_v4()?
    };
    assert_eq!(actual.map(std::num::NonZeroU32::get), Some(index));
    Ok(())
}

fn assert_unavailable(manager: &NetworkPathManager, source: &str) -> io::Result<()> {
    let source = source.parse::<SocketAddr>().map_err(io::Error::other)?;
    assert_eq!(
        manager.bind_udp(source).err().map(|error| error.kind()),
        Some(io::ErrorKind::AddrNotAvailable)
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires a fresh isolated network namespace with CAP_NET_ADMIN"]
async fn actual_isolated_dual_stack_interface_pinning_and_fail_closed_lifecycle() -> io::Result<()>
{
    super::assert_isolated_test_namespace()?;
    ip(&["link", "set", "lo", "up"])?;
    ip(&["address", "add", "192.0.2.10/32", "dev", "lo"])?;
    ip(&[
        "-6",
        "address",
        "add",
        "2001:db8::10/128",
        "dev",
        "lo",
        "nodad",
    ])?;
    ip(&["route", "add", "default", "dev", "lo", "metric", "100"])?;
    ip(&[
        "-6", "route", "add", "default", "dev", "lo", "metric", "200",
    ])?;
    let loopback = interface("lo")?;
    assert!(loopback.up && loopback.default_route);
    assert_eq!(loopback.metric, 100);
    assert!(!loopback.physical);
    let manager = NetworkPathManager::new(RoutePolicy::Interface(loopback.index))?;
    for (wildcard, expected) in [("0.0.0.0:0", "192.0.2.10"), ("[::]:0", "2001:db8::10")] {
        let socket = manager.bind_udp(wildcard.parse().map_err(io::Error::other)?)?;
        assert_pinned(&socket, loopback.index)?;
        assert_eq!(
            socket.local_addr()?.ip(),
            expected.parse::<IpAddr>().map_err(io::Error::other)?
        );
        manager.validate_bound(socket.local_addr()?)?;
        let facts = manager.candidate_interfaces(socket.local_addr()?)?;
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].index, loopback.index);
        assert_eq!(facts[0].addresses, vec![socket.local_addr()?.ip()]);
        assert_eq!(
            socket
                .recv_from(&mut [0; 1])
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        let socket = tokio::net::UdpSocket::from_std(socket)?;
        let local = socket.local_addr()?;
        let payload = b"same pinned Linux UDP socket";
        socket.send_to(payload, local).await?;
        let mut buffer = [0; 128];
        let (length, source) =
            tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut buffer))
                .await
                .map_err(io::Error::other)??;
        assert_eq!(&buffer[..length], payload);
        assert_eq!(source, local);
    }
    ip(&[
        "link",
        "add",
        "nl-path-a",
        "type",
        "veth",
        "peer",
        "name",
        "nl-path-b",
    ])?;
    ip(&["link", "set", "nl-path-a", "up"])?;
    ip(&["link", "set", "nl-path-b", "up"])?;
    ip(&["address", "add", "198.51.100.10/24", "dev", "nl-path-a"])?;
    ip(&[
        "-6",
        "address",
        "add",
        "2001:db8:1::10/64",
        "dev",
        "nl-path-a",
        "nodad",
    ])?;
    ip(&[
        "-6",
        "address",
        "add",
        "2001:db8:1::20/64",
        "dev",
        "nl-path-a",
        "preferred_lft",
        "0",
        "valid_lft",
        "60",
        "nodad",
    ])?;
    ip(&["address", "add", "203.0.113.10/24", "dev", "nl-path-b"])?;
    let selected = interface("nl-path-a")?;
    assert!(selected.up && !selected.physical);
    assert!(
        selected.addresses.contains(
            &"2001:db8:1::10"
                .parse::<IpAddr>()
                .map_err(io::Error::other)?
        )
    );
    assert!(
        !selected.addresses.contains(
            &"2001:db8:1::20"
                .parse::<IpAddr>()
                .map_err(io::Error::other)?
        )
    );
    let old = NetworkPathManager::new(RoutePolicy::Interface(selected.index))?;
    for wildcard in ["0.0.0.0:0", "[::]:0"] {
        let socket = old.bind_udp(wildcard.parse().map_err(io::Error::other)?)?;
        assert_pinned(&socket, selected.index)?;
        let facts = old.candidate_interfaces(socket.local_addr()?)?;
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].index, selected.index);
        assert_eq!(facts[0].name, selected.name);
        assert_eq!(facts[0].addresses, vec![socket.local_addr()?.ip()]);
    }
    let original = old.bind_udp("0.0.0.0:0".parse().map_err(io::Error::other)?)?;
    let original_address = original.local_addr()?;
    // Both of these IPs remain usable on another interface. The explicit
    // manager must reject them instead of borrowing a system/default socket.
    assert_unavailable(&old, "203.0.113.10:0")?;
    assert_unavailable(&old, "192.0.2.10:0")?;
    assert_unavailable(&old, "[2001:db8::10]:0")?;
    ip(&["address", "delete", "198.51.100.10/24", "dev", "nl-path-a"])?;
    ip(&["address", "add", "198.51.100.11/24", "dev", "nl-path-a"])?;
    assert_unavailable(&old, "0.0.0.0:0")?;
    assert!(old.validate_bound(original_address).is_err());
    assert!(old.candidate_interfaces(original_address).is_err());
    drop(original);
    let refreshed = NetworkPathManager::new(RoutePolicy::Interface(selected.index))?;
    let socket = refreshed.bind_udp("0.0.0.0:0".parse().map_err(io::Error::other)?)?;
    assert_eq!(
        socket.local_addr()?.ip(),
        "198.51.100.11"
            .parse::<IpAddr>()
            .map_err(io::Error::other)?
    );
    assert_pinned(&socket, selected.index)?;
    drop(socket);
    ip(&["link", "set", "nl-path-a", "down"])?;
    assert!(!interface("nl-path-a")?.up);
    assert_unavailable(&refreshed, "0.0.0.0:0")?;
    assert!(NetworkPathManager::new(RoutePolicy::Interface(selected.index)).is_err());
    ip(&["link", "set", "nl-path-a", "name", "nl-path-new"])?;
    ip(&["link", "set", "nl-path-new", "up"])?;
    assert_unavailable(&refreshed, "0.0.0.0:0")?;
    let renamed = NetworkPathManager::new(RoutePolicy::Interface(selected.index))?;
    let socket = renamed.bind_udp("0.0.0.0:0".parse().map_err(io::Error::other)?)?;
    assert_pinned(&socket, selected.index)?;
    drop(socket);
    ip(&["link", "delete", "nl-path-new"])?;
    assert_unavailable(&renamed, "0.0.0.0:0")?;
    assert!(NetworkPathManager::new(RoutePolicy::Interface(selected.index)).is_err());
    ip(&[
        "link",
        "add",
        "nl-path-new",
        "type",
        "veth",
        "peer",
        "name",
        "nl-path-peer",
    ])?;
    ip(&["link", "set", "nl-path-new", "up"])?;
    ip(&["link", "set", "nl-path-peer", "up"])?;
    ip(&["address", "add", "198.51.100.11/24", "dev", "nl-path-new"])?;
    let replacement = interface("nl-path-new")?;
    assert_ne!(replacement.index, selected.index);
    assert_unavailable(&renamed, "0.0.0.0:0")?;
    let replacement_manager = NetworkPathManager::new(RoutePolicy::Interface(replacement.index))?;
    let socket = replacement_manager.bind_udp("0.0.0.0:0".parse().map_err(io::Error::other)?)?;
    assert_pinned(&socket, replacement.index)?;
    assert!(NetworkPathManager::new(RoutePolicy::Interface(u32::MAX)).is_err());
    assert_eq!(
        NetworkPathManager::new(RoutePolicy::PreferPhysical)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::Unsupported)
    );
    println!(
        "isolated Linux media route: ipv4_ipv6_same_socket=true, pinned_ifindex={}, replacement_ifindex={}, wrong_source_down_rename_delete_no_fallback=true",
        selected.index, replacement.index
    );
    Ok(())
}
