//! Actual HTTP, two real NodeControl owners and one original group's admission.
//! This proves healthy-member isolation, not selection or an in-place switch.
use super::*;
use nestlink_protocol::{
    api::{NetworkRemoteRouteSetMemberRequest, NetworkRemoteRouteSetRequest},
    network::GrantClaims,
};

async fn reserve(
    f: &Fixture,
    second: &super::chain::ChainNode,
) -> Result<(
    String,
    [String; 2],
    nestlink_sdk::network::routed::VerifiedRemoteRouteSet,
)> {
    let original = f
        .sdk
        .network_remote_relay(f.pin.space_id(), &f.allocation)
        .await?;
    let path = GrantClaims::decode_canonical(&URL_SAFE_NO_PAD.decode(&original.path.path.claims)?)?;
    let policy = f.sdk.network_policy(f.pin.space_id()).await?;
    let a = f.control.current_lease()?;
    let b = second.control.current_lease()?;
    let expires = path
        .scope()
        .expires_at_ms
        .min(a.expires_at_unix_ms)
        .min(b.expires_at_unix_ms);
    let mut ids = [random_id(), random_id()];
    ids.sort();
    let nodes = [&f.node_id, &second.id];
    let request = NetworkRemoteRouteSetRequest {
        set_id: random_id(),
        path: NetworkRemotePathRequest {
            connectivity_grant_id: random_id(),
            path_grant_id: random_id(),
            controller_membership_grant_id: original.path.controller_membership.grant_id,
            host_membership_grant_id: original.path.host_membership.grant_id,
            expected_policy_epoch: policy.policy_epoch,
            expires_at_unix_ms: expires,
        },
        members: [0, 1].map(|index| NetworkRemoteRouteSetMemberRequest {
            allocation_id: ids[index].clone(),
            transit_grant_id: random_id(),
            node_id: nodes[index].clone(),
        }),
        device_id: f.controller.device_id.clone(),
        signature: String::new(),
    };
    let set = request.set_id.clone();
    let initial = f
        .sdk
        .reserve_verified_network_remote_route_set(
            &f.pin,
            &f.controller,
            &f.permit,
            &f.host.identity.public_key(),
            request,
        )
        .await?;
    assert!(
        initial
            .candidates()
            .iter()
            .all(|candidate| candidate.available())
    );
    let ready = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if [&f.control, &second.control]
                .into_iter()
                .enumerate()
                .all(|(index, control)| {
                    control.resource_snapshot().is_ok_and(|snapshot| {
                        snapshot.network_routes.iter().any(|resource| {
                            resource
                                .allocation
                                .as_ref()
                                .is_some_and(|allocation| allocation.allocation_id == ids[index])
                        })
                    })
                })
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    if ready.is_err() {
        for (index, control) in [&f.control, &second.control].into_iter().enumerate() {
            match control.resource_snapshot() {
                Ok(snapshot) => eprintln!(
                    "route-set node={index} expected={} current_allocations={:?}",
                    ids[index],
                    snapshot
                        .network_routes
                        .iter()
                        .filter_map(|resource| resource
                            .allocation
                            .as_ref()
                            .map(|allocation| allocation.allocation_id.as_str()))
                        .collect::<Vec<_>>()
                ),
                Err(error) => eprintln!("route-set node={index} snapshot_error={error:?}"),
            }
        }
    }
    ready.map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "original route-set resources missing from node snapshots",
        )
    })?;
    Ok((set, ids, initial))
}

#[tokio::test]
async fn original_route_set_keeps_b_admissible_after_a_stops_and_rejects_role_replay() -> Result {
    let mut f = Fixture::new().await?;
    let mut second = super::chain::ChainNode::new(&f).await?;
    let (set, ids, initial) = reserve(&f, &second).await?;
    let group = initial.transport_group();
    let path_id = initial.path_grant_id().to_owned();
    let deadline = initial.deadline();
    let bindings = initial
        .candidates()
        .map(|candidate| candidate.route_binding());
    f.control.stop();
    f.shutdown.send_replace(true);
    f.sdk.revoke_node(&f.node_id).await?;
    let refreshed = initial
        .refresh_current(
            &f.sdk,
            &f.controller,
            &f.permit,
            &f.host.identity.public_key(),
        )
        .await?;
    assert_eq!(refreshed.transport_group(), group);
    assert_eq!(refreshed.path_grant_id(), path_id);
    assert!(refreshed.deadline() <= deadline);
    assert_eq!(
        refreshed
            .candidates()
            .map(|candidate| candidate.route_binding()),
        bindings
    );
    assert!(!refreshed.candidates()[0].available());
    assert!(refreshed.candidates()[1].available());
    assert!(
        refreshed
            .candidate_for_admission(
                &f.sdk,
                &f.controller,
                &f.permit,
                &f.host.identity.public_key(),
                0
            )
            .is_none()
    );
    if let Some(task) = f.node_task.as_mut() {
        tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "stopped A task join"))???;
    }
    f.node_task = None;
    f.node
        .close_and_wait(Instant::now() + Duration::from_secs(3))
        .await?;
    let current = f
        .sdk
        .verified_network_remote_route_set(
            &f.pin,
            &f.controller,
            &f.permit,
            &f.host.identity.public_key(),
            &set,
        )
        .await?;
    assert_eq!(current.transport_group(), group);
    let candidate = current
        .candidate_for_admission(
            &f.sdk,
            &f.controller,
            &f.permit,
            &f.host.identity.public_key(),
            1,
        )
        .ok_or("healthy candidate unavailable")?;
    let uri = url::Url::parse(
        candidate
            .node()
            .endpoints
            .quic_uri
            .as_deref()
            .ok_or("node URI")?,
    )?;
    let address: SocketAddr = format!(
        "{}:{}",
        uri.host_str().ok_or("host")?,
        uri.port().ok_or("port")?
    )
    .parse()?;
    let mut endpoint = routed::AdjacencyEndpoint::bind_node(
        "127.0.0.1:0".parse()?,
        &f.controller.identity,
        candidate.relay(),
    )?;
    let bound = endpoint.local_addr()?;
    let connect_deadline = Instant::now() + Duration::from_secs(3);
    let mut adjacency = endpoint
        .connect_node(
            address,
            &f.controller.identity,
            &f.controller.device_id,
            candidate.allocation_id(),
            candidate.route_binding(),
            connect_deadline,
        )
        .await?;
    let mut replay = routed::AdjacencyEndpoint::bind_node(
        "127.0.0.1:0".parse()?,
        &f.controller.identity,
        candidate.relay(),
    )?;
    assert!(
        replay
            .connect_node(
                address,
                &f.controller.identity,
                &f.controller.device_id,
                candidate.allocation_id(),
                candidate.route_binding(),
                connect_deadline
            )
            .await
            .is_err()
    );
    replay
        .close_and_wait(Instant::now() + Duration::from_secs(3))
        .await?;
    f.sdk
        .revoke_network_remote_route_set(f.pin.space_id(), &set)
        .await?;
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if second.control.resource_snapshot().is_ok_and(|snapshot| {
                !snapshot.network_routes.iter().any(|resource| {
                    resource
                        .allocation
                        .as_ref()
                        .is_some_and(|allocation| allocation.allocation_id == ids[1])
                })
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "revoked original set retained B resource",
        )
    })?;
    adjacency
        .close_and_wait(Instant::now() + Duration::from_secs(3))
        .await?;
    let _socket = UdpSocket::bind(bound)?;
    assert!(
        f.sdk
            .verified_network_remote_route_set(
                &f.pin,
                &f.controller,
                &f.permit,
                &f.host.identity.public_key(),
                &set
            )
            .await
            .is_err()
    );
    second.finish().await?;
    f.finish().await?;
    Ok(())
}

#[tokio::test]
async fn selected_original_candidate_keeps_business_after_other_node_loss_and_stops_on_group_revoke()
-> Result {
    let mut f = Fixture::new().await?;
    let mut second = super::chain::ChainNode::new(&f).await?;
    let (set, _ids, controller_route) = reserve(&f, &second).await?;
    let host_key = f.host.identity.public_key();
    let controller_key = f.controller.identity.public_key();
    let host_route = f
        .sdk
        .verified_network_remote_route_set(&f.pin, &f.host, &f.permit, &controller_key, &set)
        .await?;
    let group = controller_route.transport_group();
    let route_binding = controller_route.candidates()[1].route_binding();
    let original_deadline = controller_route.deadline();
    let addresses = [unused_udp()?, unused_udp()?];
    let (_keep_stop, stop) = watch::channel(None);
    let (_keep_cancel, cancel) = watch::channel(false);
    let policy = AddressPolicy::new(&[])?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let (mut controller, mut host) = tokio::try_join!(
        f.sdk.connect_network_remote_route_candidate(
            controller_route,
            1,
            addresses[0],
            &f.controller,
            &host_key,
            f.setup(EndpointRole::Controller, stop.clone())?,
            &policy,
            cancel.clone(),
            deadline,
        ),
        f.sdk.connect_network_remote_route_candidate(
            host_route,
            1,
            addresses[1],
            &f.host,
            &controller_key,
            f.setup(EndpointRole::Host, stop)?,
            &policy,
            cancel,
            deadline,
        ),
    )?;
    let payload = vec![31u8; 64 * 1024];
    for chunk in payload.chunks(nestlink_protocol::FILE_CHUNK_BYTES as usize) {
        let (sent, frame) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(host.send(Channel::FileRead, chunk), controller.receive())
        })
        .await?;
        sent?;
        assert_eq!(frame?.payload, chunk);
    }
    assert_eq!(f.control.counters()?.opened_connections, 0);
    assert_eq!(second.control.counters()?.opened_connections, 2);
    let observation = controller
        .path_observation()
        .ok_or("missing original route observation")?;
    assert_eq!(observation.binding().transport_group, Some(group));
    assert_eq!(observation.binding().route_binding, Some(route_binding));
    assert_eq!(
        observation.binding().business_generation,
        f.permit.claims().connection_generation
    );
    f.control.stop();
    f.shutdown.send_replace(true);
    f.sdk.revoke_node(&f.node_id).await?;
    // Cross more than one actual management observation. A change to the
    // unused candidate must not end the selected candidate's existing I/O.
    tokio::time::sleep(Duration::from_millis(1250)).await;
    assert!(Instant::now() < original_deadline);
    assert!(controller.lease_control().remaining().is_ok());
    assert!(host.lease_control().remaining().is_ok());
    host.send(
        Channel::FileRead,
        b"healthy original backup after A stopped",
    )
    .await?;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), controller.receive())
            .await??
            .payload,
        b"healthy original backup after A stopped"
    );
    f.sdk
        .revoke_network_remote_route_set(f.pin.space_id(), &set)
        .await?;
    let (controller_report, host_report) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::try_join!(controller.wait_stopped(), host.wait_stopped())
    })
    .await??;
    assert_eq!(controller_report.reason, StopReason::Revoked);
    assert_eq!(host_report.reason, StopReason::Revoked);
    drop((controller, host));
    let _released = rebind(&addresses)?;
    second.finish().await?;
    f.finish().await?;
    Ok(())
}
