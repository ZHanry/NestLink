//! Two real node owners and an independent HTTP recovery after old-route loss.
use super::*;
use nestlink_connectivity::continuation::QualityConstraints;
use nestlink_sdk::network::routed::{ContinuousRouteSetSession, RouteSetRecoveryConfig};
use std::sync::atomic::Ordering;

fn config(bound: SocketAddr, stop: watch::Receiver<Option<StopReason>>, cancel: watch::Receiver<bool>) -> Result<RouteSetRecoveryConfig> {
    Ok(RouteSetRecoveryConfig { bind: bound, address_policy: AddressPolicy::new(&[])?,
        permissions: vec![Permission::View,Permission::FileRead], capabilities: vec!["vp8".into()],
        local_paths: PathSet::RELAY,stop,cancel,media:None })
}
async fn pair(f: &Fixture, second: &super::super::chain::ChainNode, stop: watch::Receiver<Option<StopReason>>,
    cancel: watch::Receiver<bool>, addresses: [SocketAddr;2]) -> Result<(String,ContinuousRouteSetSession,ContinuousRouteSetSession)> {
    let (set,_,controller_route) = reserve(f,second).await?;
    let host_key = f.host.identity.public_key();
    let controller_key = f.controller.identity.public_key();
    let host_route = f.sdk.verified_network_remote_route_set(&f.pin,&f.host,&f.permit,&controller_key,&set).await?;
    let policy = AddressPolicy::new(&[])?;
    let deadline = Instant::now()+Duration::from_secs(5);
    let (controller,host) = tokio::try_join!(
        f.sdk.connect_continuing_network_remote_route_candidate(controller_route,0,addresses[0],&f.controller,&host_key,
            f.setup(EndpointRole::Controller,stop.clone())?,&policy,cancel.clone(),deadline,QualityConstraints::default()),
        f.sdk.connect_continuing_network_remote_route_candidate(host_route,0,addresses[1],&f.host,&controller_key,
            f.setup(EndpointRole::Host,stop)?,&policy,cancel,deadline,QualityConstraints::default()),
    )?;
    Ok((set,controller,host))
}

#[tokio::test]
async fn full_old_path_loss_and_four_lost_http_responses_recover_one_fresh_generation_without_replay() -> Result {
    let mut f = Fixture::new().await?;
    let mut second = super::super::chain::ChainNode::new(&f).await?;
    let (_keep_stop,stop) = watch::channel(None);
    let (keep_cancel,cancel) = watch::channel(false);
    let old_addresses = [unused_udp()?,unused_udp()?];
    let (set,mut controller,mut host) = pair(&f,&second,stop.clone(),cancel.clone(),old_addresses).await?;
    let old_group = controller.channels().path_observation().ok_or("old observation")?.binding().transport_group;
    let old_c = controller.channels().sender();
    let old_h = host.channels().sender();
    let (sent,received) = tokio::join!(host.channels().send(Channel::FileRead,b"old generation file bytes"),controller.channels().receive());
    sent?;
    assert_eq!(received?.payload,b"old generation file bytes");
    // Prepare and consume a real standby once. Recovery must allocate fresh
    // IDs even though that original node already saw both peer admissions.
    let host_key = f.host.identity.public_key();
    let controller_key = f.controller.identity.public_key();
    tokio::try_join!(controller.poll(&f.sdk,&f.controller,&host_key,true),host.poll(&f.sdk,&f.host,&controller_key,true))?;
    let standby_addresses = [controller.standby_local_addr().ok_or("controller standby")?,host.standby_local_addr().ok_or("host standby")?];
    assert_eq!(second.control.counters()?.opened_connections,2);
    // Shut the original relay listener completely. No original business or
    // control packet can pass it; management HTTP remains independent.
    f.shutdown.send_replace(true);
    if let Some(task) = f.node_task.as_mut() { tokio::time::timeout(Duration::from_secs(3),task).await???; }
    f.node_task = None;
    f.node.close_and_wait(Instant::now()+Duration::from_secs(3)).await?;
    // The actual outer carrier's failure ends both old business owners. No
    // stop reason is injected and no old path is used for the new handshake.
    let (controller,host) = tokio::try_join!(
        controller.into_recovery_source(&f.sdk,&f.controller,&host_key,None),
        host.into_recovery_source(&f.sdk,&f.host,&controller_key,None),
    )?;
    let original_deadline = controller.deadline().min(host.deadline());
    assert!(old_c.send(Channel::FileRead,b"old controller request must not replay").await.is_err());
    assert!(old_h.send(Channel::FileRead,b"old host response must not replay").await.is_err());
    drop(rebind(&old_addresses)?);
    drop(rebind(&standby_addresses)?);
    for flag in [&f.recovery_faults.offer,&f.recovery_faults.approval,&f.recovery_faults.commit,&f.recovery_faults.reservation] { flag.store(true,Ordering::SeqCst); }
    let new_addresses = [unused_udp()?,unused_udp()?];
    let (mut controller,mut host) = tokio::try_join!(
        f.sdk.recover_network_route_set(&f.controller,&host_key,controller,config(new_addresses[0],stop.clone(),cancel.clone())?),
        f.sdk.recover_network_route_set(&f.host,&controller_key,host,config(new_addresses[1],stop.clone(),cancel.clone())?),
    )?;
    assert_eq!(f.recovery_faults.lost.load(Ordering::SeqCst),4);
    assert_eq!(controller.permit().claims(),host.permit().claims());
    assert_eq!(controller.permit().claims().connection_generation,f.permit.claims().connection_generation+1);
    assert_eq!(controller.permit().claims().lease_sequence,f.permit.claims().lease_sequence+1);
    assert_eq!(controller.permit().claims().expires_at_unix_ms,f.permit.claims().expires_at_unix_ms);
    assert_eq!(controller.permit().claims().permissions,f.permit.claims().permissions);
    assert!(Instant::now().into_std()+Duration::from_millis(controller.remaining_ms()?)<=original_deadline+Duration::from_millis(2));
    let observation = controller.channels().path_observation().ok_or("new observation")?;
    assert_ne!(observation.binding().transport_group,old_group);
    assert_eq!(observation.binding().business_generation,2);
    assert_eq!(second.control.counters()?.opened_connections,4);
    let file = tempfile::NamedTempFile::new()?;
    let payload = (0..8192).map(|i| (i%251) as u8).collect::<Vec<_>>();
    std::fs::write(file.path(),&payload)?;
    let from_disk = std::fs::read(file.path())?;
    let (sent,received) = tokio::join!(host.channels().send(Channel::FileRead,&from_disk),controller.channels().receive());
    sent?;
    assert_eq!(received?.payload,payload);
    assert!(old_c.send(Channel::FileRead,b"late old input/request").await.is_err());
    assert!(f.sdk.verified_network_remote_route_set(&f.pin,&f.controller,controller.permit(),&host_key,&set).await.is_err());
    keep_cancel.send_replace(true);
    let (c_stopped,h_stopped) = tokio::try_join!(controller.wait_stopped(),host.wait_stopped())?;
    assert_eq!(c_stopped.reason,StopReason::ExplicitExit);
    assert_eq!(h_stopped.reason,StopReason::ExplicitExit);
    assert!(controller.channels().send(Channel::FileRead,b"cancelled successor").await.is_err());
    drop(rebind(&new_addresses)?);
    second.finish().await?;
    f.finish().await?;
    Ok(())
}

#[tokio::test]
async fn recovery_rejects_live_sources_terminal_stops_cancel_and_narrower_local_consent_before_signing() -> Result {
    for mode in 0..4 {
        let mut f = Fixture::new().await?;
        let mut second = super::super::chain::ChainNode::new(&f).await?;
        let (_keep_stop,stop) = watch::channel(None);
        let (keep_cancel,cancel) = watch::channel(false);
        let (_,mut controller,mut host) = pair(&f,&second,stop.clone(),cancel.clone(),[unused_udp()?,unused_udp()?]).await?;
        let host_key = f.host.identity.public_key();
        if mode==0 {
            assert!(controller.into_recovery_source(&f.sdk,&f.controller,&host_key,None).await.is_err());
        } else if mode==1 {
            controller.shutdown(StopReason::Revoked).await?;
            assert!(controller.into_recovery_source(&f.sdk,&f.controller,&host_key,None).await.is_err());
        } else {
            controller.channels().lease_control().stop(StopReason::NetworkChanged)?;
            let source = controller.into_recovery_source(&f.sdk,&f.controller,&host_key,None).await?;
            let mut plan = config(unused_udp()?,stop,cancel)?;
            if mode==2 { keep_cancel.send_replace(true); } else { plan.permissions.clear(); }
            assert!(f.sdk.recover_network_route_set(&f.controller,&host_key,source,plan).await.is_err());
            assert_eq!(f.sdk.permit(&f.permit.claims().session_id).await?.claims(),f.permit.claims());
            assert!(f.sdk.reconnection_state(&f.permit.claims().session_id).await?.offer.is_none());
        }
        host.shutdown(StopReason::ExplicitExit).await?;
        second.finish().await?;
        f.finish().await?;
    }
    Ok(())
}
