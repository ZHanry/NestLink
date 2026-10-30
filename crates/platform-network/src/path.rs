//! Route policy applies to the actual media socket, including STUN discovery.
use std::{
    io,
    net::{IpAddr, SocketAddr, UdpSocket},
    sync::RwLock,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RoutePolicy {
    #[default]
    System,
    PreferPhysical,
    Interface(u32),
}

static POLICY: RwLock<RoutePolicy> = RwLock::new(RoutePolicy::System);

pub fn set_default_policy(policy: RoutePolicy) -> io::Result<()> {
    if policy == RoutePolicy::Interface(0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface index is zero",
        ));
    }
    *POLICY
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = policy;
    Ok(())
}

#[derive(Clone, Debug)]
pub struct NetworkInterface {
    pub index: u32,
    pub luid: u64,
    pub name: String,
    pub physical: bool,
    pub up: bool,
    pub metric: u32,
    pub default_route: bool,
    pub addresses: Vec<IpAddr>,
}

#[derive(Clone, Debug)]
pub struct NetworkPathManager {
    pub policy: RoutePolicy,
    pub selected: Option<NetworkInterface>,
}

impl NetworkPathManager {
    pub fn from_default() -> io::Result<Self> {
        let mut policy = *POLICY
            .read()
            .map_err(|_| io::Error::other("network policy lock poisoned"))?;
        if let Some(value) = std::env::var_os("NESTLINK_MEDIA_INTERFACE") {
            let value = value
                .to_str()
                .ok_or_else(|| io::Error::other("invalid media interface policy"))?;
            policy = match value {
                "system" => RoutePolicy::System,
                "physical" => RoutePolicy::PreferPhysical,
                value => RoutePolicy::Interface(
                    value
                        .parse::<u32>()
                        .ok()
                        .filter(|index| *index != 0)
                        .ok_or_else(|| io::Error::other("invalid media interface index"))?,
                ),
            };
        }
        Self::new(policy)
    }
    pub fn new(policy: RoutePolicy) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        if policy == RoutePolicy::PreferPhysical {
            return Err(io::Error::new(io::ErrorKind::Unsupported,
                "Linux physical-interface preference requires a trusted device classification; select an explicit interface index"));
        }
        let selected = if policy == RoutePolicy::System {
            None
        } else {
            let mut interfaces = Self::interfaces()?;
            interfaces.retain(|interface| {
                interface.up
                    && !interface.addresses.is_empty()
                    && match policy {
                        RoutePolicy::PreferPhysical => {
                            interface.physical && interface.default_route
                        }
                        RoutePolicy::Interface(index) => interface.index == index,
                        RoutePolicy::System => true,
                    }
            });
            interfaces.sort_by_key(|interface| (interface.metric, interface.index));
            Some(interfaces.into_iter().next().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "selected media interface is unavailable",
                )
            })?)
        };
        Ok(Self { policy, selected })
    }
    pub fn interfaces() -> io::Result<Vec<NetworkInterface>> {
        #[cfg(windows)]
        {
            super::windows::path_interfaces()
        }
        #[cfg(target_os = "linux")]
        {
            super::linux::path_interfaces()
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "explicit media interface routing requires Windows or Linux",
            ))
        }
    }
    pub fn allows_ip(&self, address: IpAddr) -> bool {
        self.selected
            .as_ref()
            .is_none_or(|interface| interface.addresses.contains(&address))
    }
    pub fn bind_udp(&self, address: SocketAddr) -> io::Result<UdpSocket> {
        let mut address = address;
        if let Some(interface) = &self.selected {
            if address.ip().is_unspecified() {
                address.set_ip(
                    *interface
                        .addresses
                        .iter()
                        .find(|ip| ip.is_ipv4() == address.is_ipv4())
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::AddrNotAvailable,
                                "selected media interface has no usable address for this family",
                            )
                        })?,
                );
            } else if !interface.addresses.contains(&address.ip()) {
                return Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "ICE address belongs to a different interface",
                ));
            }
            #[cfg(target_os = "linux")]
            super::linux::validate_media_interface(interface, address.ip())?;
        }
        let socket = socket2::Socket::new(
            if address.is_ipv4() {
                socket2::Domain::IPV4
            } else {
                socket2::Domain::IPV6
            },
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        if address.is_ipv6() {
            socket.set_only_v6(true)?;
        }
        #[cfg(windows)]
        super::windows::configure_media_datagrams(&socket)?;
        #[cfg(windows)]
        if let Some(interface) = &self.selected {
            super::windows::bind_media_interface(&socket, interface.index, address.is_ipv6())?;
        }
        #[cfg(target_os = "linux")]
        if let Some(interface) = &self.selected {
            super::linux::bind_media_interface(&socket, interface.index, address.is_ipv6())?;
        }
        socket.bind(&address.into())?;
        #[cfg(target_os = "linux")]
        if let Some(interface) = &self.selected {
            // Link/address changes during bind fail this attempt. The actual
            // socket remains pinned by ifindex if a later change races us;
            // NetworkMonitor invalidates its owning connection generation.
            super::linux::validate_media_interface(interface, address.ip())?;
        }
        socket.set_nonblocking(true)?;
        Ok(socket.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_policy_never_rebinds_a_candidate_to_another_interface() -> io::Result<()> {
        let manager = NetworkPathManager {
            policy: RoutePolicy::Interface(27),
            selected: Some(NetworkInterface {
                index: 27,
                luid: 1,
                name: "test".into(),
                physical: true,
                up: true,
                metric: 1,
                default_route: true,
                addresses: vec!["192.168.1.10".parse().map_err(io::Error::other)?],
            }),
        };
        assert!(
            manager
                .bind_udp("192.168.2.1:0".parse().map_err(io::Error::other)?)
                .is_err()
        );
        assert!(
            manager
                .bind_udp("[::]:0".parse().map_err(io::Error::other)?)
                .is_err()
        );
        assert!(!manager.allows_ip("192.168.2.1".parse().map_err(io::Error::other)?));
        Ok(())
    }
    #[test]
    fn system_socket_keeps_family_and_nonblocking_semantics() -> io::Result<()> {
        let manager = NetworkPathManager::new(RoutePolicy::System)?;
        let socket = manager.bind_udp("127.0.0.1:0".parse().map_err(io::Error::other)?)?;
        assert!(socket.local_addr()?.port() != 0);
        assert_eq!(
            socket
                .recv_from(&mut [0; 1])
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        Ok(())
    }
}
