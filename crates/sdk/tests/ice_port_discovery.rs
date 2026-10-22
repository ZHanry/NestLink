#![cfg(not(target_arch = "wasm32"))]
//! Exercise the pinned production ICE fork through its public API. These are
//! two routed LANs, not two peers on one virtual LAN or a forwarding proxy.
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Mutex, mpsc};
use webrtc::{
    ice::{
        agent::{Agent, agent_config::AgentConfig},
        candidate::{Candidate, CandidateType, candidate_base::unmarshal_candidate},
        mdns::MulticastDnsMode,
        network_type::NetworkType,
        udp_network::{ConnectivityEvent, EphemeralUDP, UDPNetwork},
        url::Url,
    },
    util::{
        Conn,
        vnet::{
            nat::{EndpointDependencyType as Dependency, NatType},
            net::{Net, NetConfig},
            router::{Nic, Router, RouterConfig},
        },
    },
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct Topology {
    wan: Arc<Mutex<Router>>,
    _server: Arc<Net>,
    host: Arc<Net>,
    browser: Arc<Net>,
    stun: tokio::task::JoinHandle<Result>,
    stun_conn: Arc<dyn Conn + Send + Sync>,
}

async fn attach(net: &Arc<Net>, router: &Arc<Mutex<Router>>) -> Result {
    let nic = net.get_nic()?;
    router.lock().await.add_net(nic.clone()).await?;
    nic.lock().await.set_router(router.clone()).await?;
    Ok(())
}

impl Topology {
    async fn new() -> Result<Self> {
        let wan = Arc::new(Mutex::new(Router::new(RouterConfig {
            cidr: "0.0.0.0/0".into(),
            ..Default::default()
        })?));
        let server = Arc::new(Net::new(Some(NetConfig {
            static_ip: "1.2.3.4".into(),
            ..Default::default()
        })));
        attach(&server, &wan).await?;
        let mut endpoints = Vec::new();
        for (local, public, mapping) in [
            ("192.168.0.1", "27.1.1.1", Dependency::EndpointIndependent),
            (
                "10.2.0.1",
                "28.1.1.1",
                Dependency::EndpointAddrPortDependent,
            ),
        ] {
            let lan = Arc::new(Mutex::new(Router::new(RouterConfig {
                static_ips: vec![public.into()],
                cidr: format!("{local}/24"),
                nat_type: Some(NatType {
                    mapping_behavior: mapping,
                    filtering_behavior: Dependency::EndpointAddrPortDependent,
                    ..Default::default()
                }),
                ..Default::default()
            })?));
            let endpoint = Arc::new(Net::new(Some(NetConfig {
                static_ips: vec![local.into()],
                ..Default::default()
            })));
            attach(&endpoint, &lan).await?;
            wan.lock().await.add_router(lan.clone()).await?;
            lan.lock().await.set_router(wan.clone()).await?;
            endpoints.push(endpoint);
        }
        wan.lock().await.start().await?;
        let stun_conn = server.bind("1.2.3.4:3478".parse()?).await?;
        let socket = stun_conn.clone();
        let stun = tokio::spawn(async move {
            let mut bytes = [0; 2048];
            while let Ok((size, source)) = socket.recv_from(&mut bytes).await {
                let response = nestlink_traversal::stun::response(&bytes[..size], source)?;
                socket.send_to(&response, source).await?;
            }
            Ok(())
        });
        Ok(Self {
            wan,
            _server: server,
            host: endpoints.remove(0),
            browser: endpoints.remove(0),
            stun,
            stun_conn,
        })
    }

    async fn close(self) -> Result {
        self.stun.abort();
        match self.stun.await {
            Ok(result) => result?,
            Err(error) if error.is_cancelled() => {}
            Err(error) => return Err(error.into()),
        }
        self.stun_conn.close().await?;
        self.wan.lock().await.stop().await?;
        Ok(())
    }
}

async fn agent(net: Arc<Net>, discovery: bool, probes: Arc<AtomicUsize>) -> Result<Agent> {
    let mut network = EphemeralUDP::default();
    network.set_bounded_port_discovery(discovery);
    network.set_connectivity_observer(Arc::new(move |_, event| {
        if event == ConnectivityEvent::PortDiscoveryProbe {
            probes.fetch_add(1, Ordering::SeqCst);
        }
    }));
    let agent = Agent::new(AgentConfig {
        urls: vec![Url::parse_url("stun:1.2.3.4:3478")?],
        udp_network: UDPNetwork::Ephemeral(network),
        net: Some(net),
        network_types: vec![NetworkType::Udp4],
        multicast_dns_mode: MulticastDnsMode::Disabled,
        ..Default::default()
    })
    .await?;
    let (tx, mut gathered) = mpsc::channel(8);
    agent.on_candidate(Box::new(move |candidate| {
        let tx = tx.clone();
        Box::pin(async move {
            let _ = tx.send(candidate.is_none()).await;
        })
    }));
    agent.gather_candidates()?;
    tokio::time::timeout(Duration::from_secs(2), async {
        while gathered.recv().await == Some(false) {}
    })
    .await
    .map_err(|_| "virtual candidate gathering timed out")?;
    assert!(
        agent
            .get_local_candidates()
            .await?
            .iter()
            .any(|c| c.candidate_type() == CandidateType::ServerReflexive)
    );
    Ok(agent)
}

#[tokio::test]
async fn bounded_discovery_changes_restrictive_nat_failure_into_authenticated_direct_data() -> Result
{
    for discovery in [false, true] {
        let topology = Topology::new().await?;
        let probes = Arc::new(AtomicUsize::new(0));
        let host = agent(topology.host.clone(), discovery, probes.clone()).await?;
        let browser = agent(topology.browser.clone(), false, Arc::default()).await?;
        for (from, to) in [(&host, &browser), (&browser, &host)] {
            for candidate in from.get_local_candidates().await? {
                let remote: Arc<dyn Candidate + Send + Sync> =
                    Arc::new(unmarshal_candidate(&candidate.marshal())?);
                to.add_remote_candidate(&remote)?;
            }
        }
        let (hu, hp) = host.get_local_user_credentials().await;
        let (bu, bp) = browser.get_local_user_credentials().await;
        let (_cancel_host, host_rx) = mpsc::channel(1);
        let (_cancel_browser, browser_rx) = mpsc::channel(1);
        let connected = tokio::time::timeout(Duration::from_secs(5), async {
            let (hc, bc) = tokio::try_join!(
                host.accept(host_rx, bu, bp),
                browser.dial(browser_rx, hu, hp)
            )?;
            for peer in [&host, &browser] {
                let pair = peer
                    .get_selected_candidate_pair()
                    .ok_or("missing nominated pair")?;
                assert_ne!(pair.local.candidate_type(), CandidateType::Relay);
                assert_ne!(pair.remote.candidate_type(), CandidateType::Relay);
            }
            let mut bytes = [0; 64];
            hc.send(b"direct-host-to-browser").await?;
            let size = bc.recv(&mut bytes).await?;
            assert_eq!(&bytes[..size], b"direct-host-to-browser");
            bc.send(b"direct-browser-to-host").await?;
            let size = hc.recv(&mut bytes).await?;
            assert_eq!(&bytes[..size], b"direct-browser-to-host");
            let after_connection = probes.load(Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(450)).await;
            assert_eq!(
                probes.load(Ordering::SeqCst),
                after_connection,
                "probes continued after selection"
            );
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        })
        .await;
        if discovery {
            connected??;
            assert!((1..=384).contains(&probes.load(Ordering::SeqCst)));
        } else {
            assert!(
                connected.is_err(),
                "ordinary candidates unexpectedly traversed restrictive NATs"
            );
            assert_eq!(probes.load(Ordering::SeqCst), 0);
            let checks = host.get_candidate_pairs_stats().await;
            assert!(checks.iter().any(|pair| pair.requests_sent > 0));
            assert!(
                checks
                    .iter()
                    .all(|pair| pair.requests_received == 0 && pair.responses_received == 0)
            );
        }
        host.close().await?;
        browser.close().await?;
        let after_close = probes.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(
            probes.load(Ordering::SeqCst),
            after_close,
            "probes continued after teardown"
        );
        topology.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn cancelling_connect_stops_bounded_discovery() -> Result {
    let topology = Topology::new().await?;
    let probes = Arc::new(AtomicUsize::new(0));
    let host = agent(topology.host.clone(), true, probes.clone()).await?;
    let absent = agent(topology.browser.clone(), false, Arc::default()).await?;
    for candidate in absent.get_local_candidates().await? {
        let remote: Arc<dyn Candidate + Send + Sync> =
            Arc::new(unmarshal_candidate(&candidate.marshal())?);
        host.add_remote_candidate(&remote)?;
    }
    let (ufrag, pwd) = absent.get_local_user_credentials().await;
    let (cancel, cancelled) = mpsc::channel(1);
    let (result, cancellation) = tokio::join!(host.accept(cancelled, ufrag, pwd), async {
        let started = tokio::time::timeout(Duration::from_secs(3), async {
            while probes.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        cancel.send(()).await?;
        started?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    cancellation?;
    assert!(result.is_err());
    let after_cancel = probes.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(450)).await;
    assert_eq!(probes.load(Ordering::SeqCst), after_cancel);
    host.close().await?;
    absent.close().await?;
    topology.close().await
}
