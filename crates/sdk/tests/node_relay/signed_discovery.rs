use super::*;
use nestlink_protocol::api::{Candidate, CandidateKind, NodeEndpoints, NodeEndpointsUpdate};
use nestlink_sdk::SignalCursor;
use prost::Message;
use std::net::{IpAddr, UdpSocket};

fn routed_host_address() -> Result<IpAddr> {
    // UDP connect selects a local interface without sending a packet. Binding
    // the relay listener to 0.0.0.0 lets the signed node endpoint publish this
    // literal address, which the signaling contract permits.
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("192.0.2.1:9")?;
    let address = socket.local_addr()?.ip();
    if !nestlink_protocol::signaling::safe_peer_address(address)
        || !address.is_ipv4()
        || address.is_loopback()
        || address.is_multicast()
    {
        return Err("no non-loopback routed interface is available".into());
    }
    Ok(address)
}

fn local_options() -> nestlink_sdk::native::NativeSessionOptions {
    nestlink_sdk::native::NativeSessionOptions {
        granted_permissions: vec![Permission::View],
        supported_capabilities: vec!["vp8".into()],
        local_paths: PathSet::RELAY,
    }
}

async fn approve_quic_endpoint(f: &mut Fixture, address: IpAddr) -> Result {
    let current = f.sdk.node_endpoints(&f.node_id).await?;
    assert_eq!(current.revision, 0);
    assert_eq!(current.endpoints, NodeEndpoints::default());
    let port: u16 = f
        .quic_uri
        .rsplit(':')
        .next()
        .ok_or("fixture QUIC port missing")?
        .parse()?;
    f.sdk
        .set_node_endpoints(
            &f.node_id,
            NodeEndpointsUpdate {
                expected_revision: 0,
                endpoints: NodeEndpoints {
                    quic_uri: Some(format!("quic://{address}:{port}")),
                    allow_loopback: false,
                    ..NodeEndpoints::default()
                },
            },
        )
        .await
        .map_err(|error| format!("set signed QUIC endpoint {address}:{port}: {error:?}"))?;
    let prefixes = vec![format!("{address}/32")];
    f.endpoints = [
        NativeEndpoint::new(
            "0.0.0.0:0".parse()?,
            &f.controller,
            &f.host.identity.public_key(),
            f.permit.clone(),
            vec![],
            AddressPolicy::new(&prefixes)?,
        )?,
        NativeEndpoint::new(
            "0.0.0.0:0".parse()?,
            &f.host,
            &f.controller.identity.public_key(),
            f.permit.clone(),
            vec![],
            AddressPolicy::new(&prefixes)?,
        )?,
    ];
    Ok(())
}

async fn wait_for_allocation_count(f: &Fixture, expected: u32) -> Result {
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if f.sdk.relay_reservations().await?.held_allocations == expected {
                return Ok::<(), nestlink_sdk::SdkError>(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await??;
    Ok(())
}

async fn wait_for_peer_relay_marker(f: &Fixture, peer: &DeviceIdentity) -> Result<Candidate> {
    let mut cursor = SignalCursor::new(&f.permit, peer)?;
    let marker = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            for signal in f.sdk.peer_signals(peer, &f.permit, &mut cursor).await? {
                if let Some(marker) = signal
                    .candidates
                    .into_iter()
                    .find(|candidate| candidate.kind == CandidateKind::Relay)
                {
                    return Ok::<_, nestlink_sdk::SdkError>(marker);
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    Ok(marker)
}

#[tokio::test]
async fn establish_automatically_uses_signed_shared_relay_allocation_for_relay_only() -> Result {
    let address = match routed_host_address() {
        Ok(address) => address,
        Err(_) => return Ok(()),
    };
    let mut f = Fixture::with_quic_bound(None, "0.0.0.0:0").await?;
    approve_quic_endpoint(&mut f, address).await?;
    let (_cancel, cancel) = watch::channel(false);
    let (mut controller, mut host) = tokio::try_join!(
        f.endpoints[0].establish(
            &f.sdk,
            &f.controller,
            local_options(),
            &[],
            vec![],
            cancel.clone(),
        ),
        f.endpoints[1].establish(&f.sdk, &f.host, local_options(), &[], vec![], cancel,),
    )
    .map_err(|error| format!("automatic relay-only establishment failed: {error:?}"))?;
    assert_eq!(controller.candidate.path(), Path::Relay);
    assert_eq!(host.candidate.path(), Path::Relay);
    let payload = vec![0x5a; 64 * 1024];
    let (sent, received) = tokio::join!(
        controller.channels.send(Channel::Video, &payload),
        host.channels.receive(),
    );
    sent?;
    assert_eq!(received?.payload, payload);
    let (sent, received) = tokio::join!(
        host.channels.send(Channel::Video, b"relay-only reply"),
        controller.channels.receive(),
    );
    sent?;
    assert_eq!(received?.payload, b"relay-only reply");
    controller
        .control
        .stop(nestlink_sdk::StopReason::ExplicitExit)?;
    host.control.stop(nestlink_sdk::StopReason::ExplicitExit)?;
    drop(controller);
    drop(host);
    f.closed().await?;
    f.receipts(1, 1).await?;
    Ok(())
}

#[tokio::test]
async fn establish_joins_the_existing_shared_allocation_when_capacity_is_full() -> Result {
    let address = match routed_host_address() {
        Ok(address) => address,
        Err(_) => return Ok(()),
    };
    let mut f = Fixture::with_quic_bound(None, "0.0.0.0:0").await?;
    approve_quic_endpoint(&mut f, address).await?;

    // Keep the fixture's initial reservation as the first slot, then allow one
    // more allocation. The controller consumes that last slot before the host
    // starts; the host must join the same deterministic allocation ID.
    let quota = f.sdk.relay_quota().await?;
    f.sdk
        .set_relay_quota(nestlink_protocol::api::RelayQuotaUpdate {
            expected_revision: quota.revision,
            limits: nestlink_protocol::api::RelayQuotaLimits {
                max_allocations: 2,
                ..quota.limits
            },
        })
        .await?;
    assert_eq!(f.sdk.relay_reservations().await?.held_allocations, 1);

    let (_cancel, cancel) = watch::channel(false);
    let mut controller_establish = Box::pin(f.endpoints[0].establish(
        &f.sdk,
        &f.controller,
        local_options(),
        &[],
        vec![],
        cancel.clone(),
    ));
    let wait_for_full_capacity = wait_for_allocation_count(&f, 2);
    tokio::pin!(wait_for_full_capacity);
    tokio::select! {
        result = &mut controller_establish => return Err(match result {
            Ok(_) => "controller established before its peer joined".to_owned(),
            Err(error) => format!("controller failed before its peer joined: {error:?}"),
        }.into()),
        result = &mut wait_for_full_capacity => result?,
    }
    assert_eq!(f.sdk.relay_reservations().await?.held_allocations, 2);

    let (controller, host) = tokio::try_join!(
        &mut controller_establish,
        f.endpoints[1].establish(&f.sdk, &f.host, local_options(), &[], vec![], cancel,),
    )
    .map_err(|error| format!("capacity-full relay rendezvous failed: {error:?}"))?;
    assert_eq!(controller.candidate.path(), Path::Relay);
    assert_eq!(host.candidate.path(), Path::Relay);
    assert_eq!(f.sdk.relay_reservations().await?.held_allocations, 2);
    controller
        .control
        .stop(nestlink_sdk::StopReason::ExplicitExit)?;
    host.control.stop(nestlink_sdk::StopReason::ExplicitExit)?;
    drop(controller);
    drop(host);
    f.closed().await?;
    f.receipts(1, 1).await?;
    Ok(())
}

#[tokio::test]
async fn establish_rendezvous_refreshes_allocation_after_node_endpoint_revision_changes() -> Result
{
    let address = match routed_host_address() {
        Ok(address) => address,
        Err(_) => return Ok(()),
    };
    let mut f = Fixture::with_quic_bound(None, "0.0.0.0:0").await?;
    approve_quic_endpoint(&mut f, address).await?;
    let (_cancel, cancel) = watch::channel(false);
    let mut controller_establish = Box::pin(f.endpoints[0].establish(
        &f.sdk,
        &f.controller,
        local_options(),
        &[],
        vec![],
        cancel.clone(),
    ));
    let wait_for_marker = wait_for_peer_relay_marker(&f, &f.host);
    tokio::pin!(wait_for_marker);
    let marker = tokio::select! {
        result = &mut controller_establish => return Err(match result {
            Ok(_) => "controller established before its peer joined".to_owned(),
            Err(error) => format!("controller failed before its peer joined: {error:?}"),
        }.into()),
        result = &mut wait_for_marker => result?,
    };
    assert_eq!(marker.kind, CandidateKind::Relay);

    let port: u16 = f
        .quic_uri
        .rsplit(':')
        .next()
        .ok_or("fixture QUIC port missing")?
        .parse()?;
    f.sdk
        .set_node_endpoints(
            &f.node_id,
            NodeEndpointsUpdate {
                expected_revision: 1,
                endpoints: NodeEndpoints {
                    quic_uri: Some(format!("quic://{address}:{port}")),
                    allow_loopback: false,
                    ..NodeEndpoints::default()
                },
            },
        )
        .await?;

    let (controller, host) = tokio::try_join!(
        &mut controller_establish,
        f.endpoints[1].establish(&f.sdk, &f.host, local_options(), &[], vec![], cancel,),
    )?;
    assert_eq!(controller.candidate.path(), Path::Relay);
    assert_eq!(host.candidate.path(), Path::Relay);
    controller
        .control
        .stop(nestlink_sdk::StopReason::ExplicitExit)?;
    host.control.stop(nestlink_sdk::StopReason::ExplicitExit)?;
    drop(controller);
    drop(host);
    f.closed().await?;
    // The old revision's promise remains held alongside the fixture grant;
    // only the allocation used by the successful current-revision pair closes.
    f.receipts(1, 2).await?;
    Ok(())
}

impl Fixture {
    pub(super) async fn approve_locations(&mut self) -> Result<nestlink_sdk::NodeDiscovery> {
        let v = self.sdk.node_endpoints(&self.node_id).await?;
        assert_eq!(v.revision, 0);
        assert_eq!(v.endpoints, NodeEndpoints::default());
        assert!(
            self.sdk
                .discover_relay_nodes(&self.controller, &self.permit)
                .await?
                .nodes()
                .is_empty()
        );
        self.sdk
            .set_node_endpoints(
                &self.node_id,
                NodeEndpointsUpdate {
                    expected_revision: 0,
                    endpoints: NodeEndpoints {
                        quic_uri: Some(self.quic_uri.clone()),
                        wss_origin: Some(self.origin.clone()),
                        allow_loopback: true,
                    },
                },
            )
            .await?;
        let discovery = self
            .sdk
            .discover_relay_nodes(&self.controller, &self.permit)
            .await?;
        self.allocation = self
            .sdk
            .reserve_relay_allocation(&self.controller, &self.permit, &random_id(), &self.node_id)
            .await?;
        assert_eq!(self.allocation.claims().node_endpoint_revision, 1);
        Ok(discovery)
    }
}
#[tokio::test]
async fn signed_node_discovery_drives_real_wss_inner_tls_and_revision_update_closes_both_peers()
-> Result {
    let mut f = Fixture::new().await?;
    let d = f.approve_locations().await?;
    let host = f.sdk.discover_relay_nodes(&f.host, &f.permit).await?;
    assert_eq!(d.nodes().len(), host.nodes().len());
    assert_eq!(d.nodes()[0].node_id, host.nodes()[0].node_id);
    assert_eq!(
        d.nodes()[0].endpoint_revision,
        host.nodes()[0].endpoint_revision
    );
    let (wss, quic) = f
        .sdk
        .discovered_node_routes(&d, &f.controller, &f.permit, &f.allocation)
        .await?;
    assert!(quic.is_some());
    let wss = wss.ok_or("missing WSS")?;
    let (mut c, mut h, _keep, _clocks) = f.channels_on_route(NativeRelayRoute::Wss(&wss)).await?;
    let payload = vec![53; 256 * 1024];
    let (sent, received) = tokio::join!(h.send(Channel::Video, &payload), c.receive());
    sent?;
    assert_eq!(received?.payload, payload);
    let (sent, received) = tokio::join!(
        c.send(Channel::Video, b"signed discovery reverse"),
        h.receive()
    );
    sent?;
    assert_eq!(received?.payload, b"signed discovery reverse");
    let start = Instant::now();
    f.sdk
        .set_node_endpoints(
            &f.node_id,
            NodeEndpointsUpdate {
                expected_revision: 1,
                endpoints: NodeEndpoints::default(),
            },
        )
        .await?;
    let (c, h) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(2), c.receive()),
        tokio::time::timeout(Duration::from_secs(2), h.receive())
    );
    assert!(c?.is_err());
    assert!(h?.is_err());
    assert!(start.elapsed() < Duration::from_secs(2));
    f.closed().await?;
    assert!(
        f.sdk
            .discover_relay_nodes(&f.controller, &f.permit)
            .await?
            .nodes()
            .is_empty()
    );
    // The earlier unused grant still holds its promise; only the committed
    // pair provides actual close evidence and releases its exact two slots.
    f.receipts(1, 1).await?;
    Ok(())
}
#[tokio::test]
async fn signed_node_discovery_drives_actual_outer_and_inner_quic_with_both_endpoint_proofs()
-> Result {
    let mut f = Fixture::new().await?;
    let d = f.approve_locations().await?;
    let (_, quic) = f
        .sdk
        .discovered_node_routes(&d, &f.controller, &f.permit, &f.allocation)
        .await?;
    let quic = quic.ok_or("missing QUIC")?;
    let (mut c, mut h, _keep, _clocks) = f.channels_on_route(NativeRelayRoute::Quic(&quic)).await?;
    let (sent, received) = tokio::join!(
        c.send(Channel::Video, b"signed node virtual UDP"),
        h.receive()
    );
    sent?;
    assert_eq!(received?.payload, b"signed node virtual UDP");
    let (sent, received) = tokio::join!(h.send(Channel::Video, b"reverse inner QUIC"), c.receive());
    sent?;
    assert_eq!(received?.payload, b"reverse inner QUIC");
    Ok(())
}
#[tokio::test]
async fn signed_node_discovery_rejects_old_revision_wrong_endpoint_and_issuer_before_dns() -> Result
{
    let mut f = Fixture::new().await?;
    let old = f.allocation.clone();
    let d = f.approve_locations().await?;
    assert!(
        f.sdk
            .discovered_node_routes(&d, &f.controller, &f.permit, &old)
            .await
            .is_err()
    );
    assert!(
        f.sdk
            .discovered_node_routes(&d, &f.host, &f.permit, &f.allocation)
            .await
            .is_err()
    );
    let rogue = PermitSigner::generate();
    let forged = nestlink_identity::relay::verify_relay_allocation(
        &rogue
            .sign_relay_allocation(f.allocation.claims())?
            .encode_to_vec(),
        &rogue.public_key(),
    )?;
    assert!(
        f.sdk
            .discovered_node_routes(&d, &f.controller, &f.permit, &forged)
            .await
            .is_err()
    );
    f.sdk
        .set_node_endpoints(
            &f.node_id,
            NodeEndpointsUpdate {
                expected_revision: 1,
                endpoints: NodeEndpoints {
                    wss_origin: Some("https://must-not-resolve.invalid".into()),
                    ..NodeEndpoints::default()
                },
            },
        )
        .await?;
    let next = f
        .sdk
        .reserve_relay_allocation(&f.controller, &f.permit, &random_id(), &f.node_id)
        .await?;
    let start = Instant::now();
    assert!(matches!(
        f.sdk
            .discovered_node_routes(&d, &f.controller, &f.permit, &next)
            .await,
        Err(nestlink_sdk::SdkError::Trust)
    ));
    assert!(start.elapsed() < Duration::from_millis(250));
    Ok(())
}
#[tokio::test]
async fn signed_node_discovery_routes_keep_original_request_deadline_across_reuse() -> Result {
    let mut f = Fixture::new().await?;
    let d = f.approve_locations().await?;
    let (wss, quic) = f
        .sdk
        .discovered_node_routes(&d, &f.controller, &f.permit, &f.allocation)
        .await?;
    let wss = wss.ok_or("missing WSS")?;
    let quic = quic.ok_or("missing QUIC")?;
    tokio::time::sleep(Duration::from_millis(
        nestlink_protocol::NODE_DISCOVERY_MS + 100,
    ))
    .await;
    let start = Instant::now();
    assert!(
        f.sdk
            .discovered_node_routes(&d, &f.controller, &f.permit, &f.allocation)
            .await
            .is_err()
    );
    assert!(NativeRelayRoute::Wss(&wss).candidates(1).is_err());
    assert!(NativeRelayRoute::Quic(&quic).candidates(1).is_err());
    assert!(
        wss.connect_at(&f.controller, &f.permit, wss.addresses()[0])
            .await
            .is_err()
    );
    assert!(
        quic.connect_at(&f.controller, &f.permit, quic.addresses()[0])
            .await
            .is_err()
    );
    assert!(start.elapsed() < Duration::from_millis(250));
    assert_eq!(f.control.counters()?.opened_connections, 0);
    Ok(())
}
