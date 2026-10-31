//! Real HTTP, two NodeControl owners, original business I/O and inner-TLS spare.
use super::*;
use nestlink_connectivity::continuation::{QualityConstraints, RouteIdentity};

#[tokio::test]
async fn actual_continuous_owner_prepares_and_probes_spare_without_replacing_business_and_retires_it() -> Result {
    let mut f = Fixture::new().await?;
    let mut second = super::super::chain::ChainNode::new(&f).await?;
    let (set, _ids, controller_route) = reserve(&f, &second).await?;
    let host_key = f.host.identity.public_key();
    let controller_key = f.controller.identity.public_key();
    let host_route = f.sdk.verified_network_remote_route_set(&f.pin, &f.host, &f.permit, &controller_key, &set).await?;
    let group = controller_route.transport_group();
    let bindings = controller_route.candidates().map(|c| c.route_binding());
    let active = RouteIdentity { transport_group: group, route_binding: bindings[1] };
    let spare = RouteIdentity { transport_group: group, route_binding: bindings[0] };
    let addresses = [unused_udp()?, unused_udp()?];
    let (_keep_stop, stop) = watch::channel(None);
    let (_keep_cancel, cancel) = watch::channel(false);
    let policy = AddressPolicy::new(&[])?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let (mut controller, mut host) = tokio::try_join!(
        f.sdk.connect_continuing_network_remote_route_candidate(controller_route, 1, addresses[0], &f.controller,
            &host_key, f.setup(EndpointRole::Controller, stop.clone())?, &policy, cancel.clone(), deadline, QualityConstraints::default()),
        f.sdk.connect_continuing_network_remote_route_candidate(host_route, 1, addresses[1], &f.host,
            &controller_key, f.setup(EndpointRole::Host, stop)?, &policy, cancel, deadline, QualityConstraints::default()),
    )?;
    let (sent, received) = tokio::join!(host.channels().send(Channel::FileRead, b"original business before standby"), controller.channels().receive());
    sent?;
    assert_eq!(received?.payload, b"original business before standby");
    let (c, h) = tokio::try_join!(
        controller.poll(&f.sdk, &f.controller, &host_key, true),
        host.poll(&f.sdk, &f.host, &controller_key, true),
    )?;
    assert_eq!(c.policy.active, Some(active));
    assert_eq!(h.policy.active, Some(active));
    assert_eq!(c.policy.standby, Some(spare));
    assert_eq!(h.policy.standby, Some(spare));
    assert!(c.policy.outstanding_work.is_none());
    assert!(h.policy.outstanding_work.is_none());
    let spare_addresses = [controller.standby_local_addr().ok_or("missing controller physical spare")?,
        host.standby_local_addr().ok_or("missing host physical spare")?];
    assert_eq!(f.control.counters()?.opened_connections, 2);
    assert_eq!(second.control.counters()?.opened_connections, 2);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let (c, h) = tokio::try_join!(
        controller.poll(&f.sdk, &f.controller, &host_key, true),
        host.poll(&f.sdk, &f.host, &controller_key, true),
    )?;
    assert_eq!(c.policy.standby, Some(spare));
    assert_eq!(h.policy.standby, Some(spare));
    assert!(c.policy.outstanding_work.is_none());
    assert!(h.policy.outstanding_work.is_none());
    assert_eq!(c.policy.epoch, 1);
    assert_eq!(h.policy.epoch, 1);
    let mut observation = controller.channels().path_observation().ok_or("missing original observation")?;
    let before = observation.timed_snapshot().map(|(at, _)| at);
    let (sent, received) = tokio::join!(host.channels().send(Channel::FileRead, b"fresh original feedback"), controller.channels().receive());
    sent?;
    assert_eq!(received?.payload, b"fresh original feedback");
    let (at, measured) = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(value) = observation.timed_snapshot()
                && before.is_none_or(|old| value.0 > old) { break Ok::<_, io::Error>(value); }
            observation.changed().await.map_err(io::Error::other)?;
        }
    }).await??;
    assert_eq!(observation.timed_snapshot().map(|(same, _)| same), Some(at));
    assert_eq!(measured.binding.transport_group, Some(group));
    assert_eq!(measured.binding.route_binding, Some(bindings[1]));
    f.control.stop();
    f.shutdown.send_replace(true);
    f.sdk.revoke_node(&f.node_id).await?;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let (c, h) = tokio::try_join!(
        controller.poll(&f.sdk, &f.controller, &host_key, true),
        host.poll(&f.sdk, &f.host, &controller_key, true),
    )?;
    assert_eq!(c.policy.active, Some(active));
    assert_eq!(h.policy.active, Some(active));
    assert_eq!(c.policy.standby, None);
    assert_eq!(h.policy.standby, None);
    assert_eq!(c.policy.pending_retirements, 0);
    assert_eq!(h.policy.pending_retirements, 0);
    let _released_spares = rebind(&spare_addresses)?;
    let (sent, received) = tokio::join!(host.channels().send(Channel::FileRead, b"original business after spare withdrawal"), controller.channels().receive());
    sent?;
    assert_eq!(received?.payload, b"original business after spare withdrawal");
    f.sdk.revoke_network_remote_route_set(f.pin.space_id(), &set).await?;
    tokio::try_join!(controller.shutdown(StopReason::Revoked), host.shutdown(StopReason::Revoked))?;
    assert!(observation.timed_snapshot().is_none());
    let _released_active = rebind(&addresses)?;
    second.finish().await?;
    f.finish().await?;
    Ok(())
}
