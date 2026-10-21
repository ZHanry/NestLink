//! Supply real OS addresses without webrtc-util 0.12's Windows IPv6 word swap.
//! Net::Ifs uses actual OS sockets, DNS and mDNS; it is not a virtual topology.
use std::{collections::BTreeMap, io, net::SocketAddr};
use webrtc::util::vnet::{interface::Interface, net::Net};

pub(super) fn os_ice_network() -> io::Result<Net> {
    let mut interfaces = BTreeMap::<String, Vec<_>>::new();
    for address in if_addrs::get_if_addrs()? {
        if !address.is_oper_up() || address.is_link_local() {
            continue;
        }
        let ip = address.ip();
        if ip.is_unspecified() || ip.is_multicast() {
            continue;
        }
        let ipnet = Interface::convert(SocketAddr::new(ip, 0), None).map_err(io::Error::other)?;
        let addresses = interfaces.entry(address.name).or_default();
        if !addresses.contains(&ipnet) {
            addresses.push(ipnet);
        }
    }
    Ok(Net::Ifs(
        interfaces
            .into_iter()
            .map(|(name, addresses)| Interface::new(name, addresses))
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::Arc, time::Duration};
    use tokio::sync::mpsc;
    use webrtc::{
        api::{APIBuilder, setting_engine::SettingEngine},
        peer_connection::{
            configuration::RTCConfiguration, peer_connection_state::RTCPeerConnectionState,
        },
    };

    type Result = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

    #[tokio::test]
    async fn ice_snapshot_retains_exact_os_ipv6_octets() -> Result {
        let network = os_ice_network()?;
        assert!(!network.is_virtual());
        let actual = network.get_interfaces().await;
        for address in if_addrs::get_if_addrs()? {
            if address.is_oper_up() && !address.is_link_local() && address.ip().is_ipv6() {
                assert!(actual.iter().any(|interface| {
                    interface.name() == address.name
                        && interface.addrs().iter().any(|ip| ip.addr() == address.ip())
                }));
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn real_ipv6_ice_connection_uses_os_snapshot_and_transfers_data() -> Result {
        // IPv6 loopback requires no public Internet or configurable CI adapter.
        // Both peers use the same production snapshot and real UDP/DTLS/SCTP.
        let snapshot = os_ice_network()?;
        let v6_loopback = "::1".parse::<std::net::IpAddr>()?;
        assert!(snapshot.get_interfaces().await.iter().any(|interface| {
            interface
                .addrs()
                .iter()
                .any(|address| address.addr() == v6_loopback)
        }));
        let make_peer = || async {
            let mut settings = SettingEngine::default();
            settings.set_vnet(Some(Arc::new(os_ice_network()?)));
            settings.set_ip_filter(Box::new(move |ip| ip == v6_loopback));
            settings.set_include_loopback_candidate(true);
            let peer = APIBuilder::new()
                .with_setting_engine(settings)
                .build()
                .new_peer_connection(RTCConfiguration::default())
                .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(peer)
        };
        let first = make_peer().await?;
        let second = make_peer().await?;
        let (received, mut messages) = mpsc::channel(1);
        second.on_data_channel(Box::new(move |channel| {
            let received = received.clone();
            Box::pin(async move {
                channel.on_message(Box::new(move |message| {
                    let received = received.clone();
                    Box::pin(async move {
                        let _ = received.send(message.data).await;
                    })
                }));
            })
        }));
        let channel = first
            .create_data_channel("ipv6-direct-regression", None)
            .await?;
        let send = channel.clone();
        channel.on_open(Box::new(move || {
            let send = send.clone();
            Box::pin(async move {
                let _ = send.send_text("actual IPv6 direct").await;
            })
        }));
        let exchange = async {
            let mut gathered = first.gathering_complete_promise().await;
            first
                .set_local_description(first.create_offer(None).await?)
                .await?;
            let _ = gathered.recv().await;
            let offer = first.local_description().await.ok_or("offer missing")?;
            assert!(
                offer
                    .sdp
                    .lines()
                    .any(|line| line.starts_with("a=candidate:") && line.contains(" ::1 "))
            );
            second.set_remote_description(offer).await?;
            let mut gathered = second.gathering_complete_promise().await;
            second
                .set_local_description(second.create_answer(None).await?)
                .await?;
            let _ = gathered.recv().await;
            first
                .set_remote_description(second.local_description().await.ok_or("answer missing")?)
                .await?;
            assert_eq!(
                messages.recv().await.ok_or("data channel closed")?.as_ref(),
                b"actual IPv6 direct"
            );
            assert_eq!(first.connection_state(), RTCPeerConnectionState::Connected);
            assert_eq!(second.connection_state(), RTCPeerConnectionState::Connected);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let result = tokio::time::timeout(Duration::from_secs(10), exchange).await;
        first.close().await?;
        second.close().await?;
        result??;
        Ok(())
    }
}
