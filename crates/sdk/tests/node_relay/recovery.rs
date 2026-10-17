use super::*;
use nestlink_sdk::{
    NativeReconnectionConfig,
    native_recovery::{RecoveredNativeSession, RecoveryError, RecoveryStage, RelayRecoveryConfig},
};
use nestlink_session::StopReason;
fn config<'a>(
    f: &'a Fixture,
    stop: watch::Receiver<Option<StopReason>>,
    cancel: watch::Receiver<bool>,
    progress: watch::Sender<RecoveryStage>,
) -> Result<RelayRecoveryConfig<'a>> {
    Ok(RelayRecoveryConfig {
        endpoint: NativeReconnectionConfig {
            bound: "0.0.0.0:0".parse()?,
            stun_servers: vec![],
            address_policy: AddressPolicy::new(&[])?,
            monitor: None,
        },
        node_id: &f.node_id,
        permissions: vec![Permission::View],
        capabilities: vec!["vp8".into()],
        local_paths: PathSet::RELAY,
        stop,
        cancel,
        progress: Some(progress),
    })
}
async fn verify_data(c: &mut RecoveredNativeSession, h: &mut RecoveredNativeSession) -> Result {
    let bytes = vec![41; 256 * 1024];
    let (sent, received) = tokio::join!(
        c.channels().send(Channel::Video, &bytes),
        h.channels_mut().receive()
    );
    sent?;
    assert_eq!(received?.payload, bytes);
    let (sent, received) = tokio::join!(
        h.channels()
            .send(Channel::Video, b"automatic recovery reverse"),
        c.channels_mut().receive()
    );
    sent?;
    assert_eq!(received?.payload, b"automatic recovery reverse");
    Ok(())
}
async fn recover_real_pair(quic: bool) -> Result {
    let mut f = Fixture::new().await?;
    let d = f.approve_locations().await?;
    let (wss, qr) = f
        .sdk
        .discovered_node_routes(&d, &f.controller, &f.permit, &f.allocation)
        .await?;
    let route = if quic {
        NativeRelayRoute::Quic(qr.as_ref().ok_or("missing QUIC")?)
    } else {
        NativeRelayRoute::Wss(wss.as_ref().ok_or("missing WSS")?)
    };
    let (c, h, _old_keep, _) = f.native_sessions_on_route(route).await?;
    let old_c = c.channels.sender();
    let old_h = h.channels.sender();
    let (_cancel_keep, cancel) = watch::channel(false);
    let (_stop_keep, stop) = watch::channel(None);
    let (cp, cp_view) = watch::channel(RecoveryStage::Waiting);
    let (hp, hp_view) = watch::channel(RecoveryStage::Waiting);
    let ckey = f.controller.identity.public_key();
    let hkey = f.host.identity.public_key();
    // The recovery owners wait while an independent fact invalidates only the
    // controller's endpoint. The idle host observes the real carrier closure.
    let trigger = async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        f.endpoints[0].invalidate_network(2)
    };
    let observations = async {
        let trace = |mut stages: watch::Receiver<RecoveryStage>| async move {
            let mut result = Vec::new();
            loop {
                let stage = *stages.borrow_and_update();
                result.push(stage);
                if matches!(
                    stage,
                    RecoveryStage::Ready | RecoveryStage::Failed | RecoveryStage::Stopped(_)
                ) {
                    break;
                }
                if stages.changed().await.is_err() {
                    break;
                }
            }
            result
        };
        tokio::join!(trace(cp_view.clone()), trace(hp_view.clone()))
    };
    let (c, h, trigger, observed) = tokio::join!(
        f.sdk.recover_native_relay(
            &f.controller,
            &hkey,
            c,
            config(&f, stop.clone(), cancel.clone(), cp)?
        ),
        f.sdk.recover_native_relay(
            &f.host,
            &ckey,
            h,
            config(&f, stop.clone(), cancel.clone(), hp)?
        ),
        trigger,
        observations
    );
    trigger?;
    let mut c = c.map_err(|e| {
        format!(
            "controller recovery {e:?}; observed {observed:?}; host result {}",
            h.as_ref()
                .err()
                .map(|e| format!("{e:?}"))
                .unwrap_or_default()
        )
    })?;
    let mut h = h.map_err(|e| format!("host recovery {e:?}; observed {observed:?}"))?;
    assert_eq!(*cp_view.borrow(), RecoveryStage::Ready);
    assert_eq!(*hp_view.borrow(), RecoveryStage::Ready);
    assert_eq!(c.permit().claims(), h.permit().claims());
    assert_eq!(c.permit().claims().connection_generation, 2);
    assert_eq!(
        c.permit().claims().expires_at_unix_ms,
        f.permit.claims().expires_at_unix_ms
    );
    assert!(old_c.send(Channel::Video, b"old generation").await.is_err());
    assert!(old_h.send(Channel::Video, b"old generation").await.is_err());
    verify_data(&mut c, &mut h).await?;
    if quic {
        // A successor keeps the shared QUIC endpoint live. Its predecessor
        // cannot claim a driver drain until idle is independently observed.
        tokio::time::timeout(Duration::from_secs(3), async {
            while f.control.close_report_status()?.active_allocations != 1 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok::<(), nestlink_node::control::Error>(())
        })
        .await??;
        let acknowledged = f.control.close_report_status()?.acknowledged_receipts;
        assert_eq!(
            f.sdk.relay_reservations().await?.held_allocations,
            3 - acknowledged as u32
        );
    } else {
        f.receipts(1, 2).await?;
    }
    if !quic {
        eprintln!("first recovery carried bidirectional data; starting generation 3");
        // A second automatic exchange ignores the previous signed receipt and
        // derives one further UUID shared by both independent endpoint owners.
        c.endpoint().invalidate_network(2)?;
        let (cs, _c_endpoint, _c_receipt) = c.into_parts();
        let (hs, _h_endpoint, _h_receipt) = h.into_parts();
        let (cp, mut cpv) = watch::channel(RecoveryStage::Waiting);
        let (hp, mut hpv) = watch::channel(RecoveryStage::Waiting);
        let observed = async {
            let mut stages = Vec::new();
            loop {
                let c = *cpv.borrow_and_update();
                let h = *hpv.borrow_and_update();
                if stages.last() != Some(&(c, h)) {
                    stages.push((c, h));
                }
                let c_done = matches!(
                    c,
                    RecoveryStage::Ready | RecoveryStage::Failed | RecoveryStage::Stopped(_)
                );
                let h_done = matches!(
                    h,
                    RecoveryStage::Ready | RecoveryStage::Failed | RecoveryStage::Stopped(_)
                );
                if c_done && h_done {
                    break;
                }
                tokio::select! { _ = cpv.changed(), if !c_done => {}, _ = hpv.changed(), if !h_done => {} }
            }
            stages
        };
        let (next_c, next_h, stages) = tokio::join!(
            f.sdk.recover_native_relay(
                &f.controller,
                &hkey,
                cs,
                config(&f, stop.clone(), cancel.clone(), cp)?
            ),
            f.sdk
                .recover_native_relay(&f.host, &ckey, hs, config(&f, stop, cancel, hp)?),
            observed
        );
        eprintln!(
            "second controller={:?}; host={:?}; stages={stages:?}",
            next_c.as_ref().err(),
            next_h.as_ref().err()
        );
        c = next_c?;
        h = next_h?;
        assert_eq!(c.permit().claims().connection_generation, 3);
        assert_eq!(c.permit().claims(), h.permit().claims());
        f.receipts(2, 2).await?;
        verify_data(&mut c, &mut h).await?;
    }
    Ok(())
}
#[tokio::test]
async fn idle_wss_failure_automatically_exchanges_proofs_and_rebuilds_twice() -> Result {
    recover_real_pair(false).await
}
#[tokio::test]
async fn idle_inner_quic_network_loss_notifies_peer_and_automatically_rebuilds() -> Result {
    recover_real_pair(true).await
}
#[tokio::test]
async fn recovery_exit_while_waiting_stops_old_handles_without_advancing_consent() -> Result {
    let f = Fixture::new().await?;
    let route = f
        .sdk
        .node_relay_route(&f.origin, true, &f.permit, &f.allocation)
        .await?;
    let (c, mut h, _keep, _) = f
        .native_sessions_on_route(NativeRelayRoute::Wss(&route))
        .await?;
    let sender = c.channels.sender();
    let (cancel_keep, cancel) = watch::channel(false);
    let (_stop_keep, stop) = watch::channel(None);
    let (progress, view) = watch::channel(RecoveryStage::Waiting);
    let key = f.host.identity.public_key();
    let exit = async {
        tokio::time::sleep(Duration::from_millis(30)).await;
        cancel_keep.send_replace(true);
    };
    let (result, ()) = tokio::join!(
        f.sdk
            .recover_native_relay(&f.controller, &key, c, config(&f, stop, cancel, progress)?),
        exit
    );
    assert!(matches!(
        result,
        Err(RecoveryError::Stopped(StopReason::ExplicitExit))
    ));
    assert_eq!(
        *view.borrow(),
        RecoveryStage::Stopped(StopReason::ExplicitExit)
    );
    assert!(sender.send(Channel::Video, b"exited").await.is_err());
    h.channels.wait_stopped().await?;
    assert_eq!(
        f.sdk
            .permit(&f.permit.claims().session_id)
            .await?
            .claims()
            .connection_generation,
        1
    );
    Ok(())
}
#[tokio::test]
async fn recovery_cancellation_interrupts_host_proof_wait_and_never_commits() -> Result {
    let f = Fixture::new().await?;
    let route = f
        .sdk
        .node_relay_route(&f.origin, true, &f.permit, &f.allocation)
        .await?;
    let (mut c, h, _keep, _) = f
        .native_sessions_on_route(NativeRelayRoute::Wss(&route))
        .await?;
    f.endpoints[0].invalidate_network(2)?;
    let (cancel_keep, cancel) = watch::channel(false);
    let (_stop_keep, stop) = watch::channel(None);
    let (progress, mut view) = watch::channel(RecoveryStage::Waiting);
    let key = f.controller.identity.public_key();
    let exit = async {
        loop {
            if *view.borrow_and_update() == RecoveryStage::ExchangingProofs {
                break;
            }
            view.changed().await?;
        }
        cancel_keep.send_replace(true);
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    };
    let start = Instant::now();
    let (result, exit) = tokio::join!(
        f.sdk
            .recover_native_relay(&f.host, &key, h, config(&f, stop, cancel, progress)?),
        exit
    );
    exit?;
    assert!(matches!(
        result,
        Err(RecoveryError::Stopped(StopReason::ExplicitExit))
    ));
    assert!(start.elapsed() < Duration::from_secs(2));
    c.channels.wait_stopped().await?;
    assert_eq!(
        f.sdk
            .permit(&f.permit.claims().session_id)
            .await?
            .claims()
            .connection_generation,
        1
    );
    Ok(())
}
#[tokio::test]
async fn terminal_cleanup_local_policy_and_peer_binding_prevent_automatic_consent() -> Result {
    for reason in [
        StopReason::Revoked,
        StopReason::ExplicitExit,
        StopReason::Suspended,
        StopReason::ProtocolViolation,
    ] {
        let f = Fixture::new().await?;
        let route = f
            .sdk
            .node_relay_route(&f.origin, true, &f.permit, &f.allocation)
            .await?;
        let (c, mut h, _keep, _) = f
            .native_sessions_on_route(NativeRelayRoute::Wss(&route))
            .await?;
        c.channels.lease_control().stop(reason)?;
        let (_cancel_keep, cancel) = watch::channel(false);
        let (_stop_keep, stop) = watch::channel(None);
        let (progress, _) = watch::channel(RecoveryStage::Waiting);
        let result = f
            .sdk
            .recover_native_relay(
                &f.controller,
                &f.host.identity.public_key(),
                c,
                config(&f, stop, cancel, progress)?,
            )
            .await;
        assert!(matches!(result, Err(RecoveryError::Stopped(actual)) if actual == reason));
        h.channels.wait_stopped().await?;
        assert_eq!(
            f.sdk
                .permit(&f.permit.claims().session_id)
                .await?
                .claims()
                .connection_generation,
            1
        );
    }
    for bad_peer in [false, true] {
        let f = Fixture::new().await?;
        let route = f
            .sdk
            .node_relay_route(&f.origin, true, &f.permit, &f.allocation)
            .await?;
        let (c, mut h, _keep, _) = f
            .native_sessions_on_route(NativeRelayRoute::Wss(&route))
            .await?;
        f.endpoints[0].invalidate_network(2)?;
        let (_cancel_keep, cancel) = watch::channel(false);
        let (_stop_keep, stop) = watch::channel(None);
        let (progress, _) = watch::channel(RecoveryStage::Waiting);
        let mut plan = config(&f, stop, cancel, progress)?;
        if !bad_peer {
            plan.local_paths = PathSet::DIRECT;
        }
        let key = if bad_peer {
            [0; 32]
        } else {
            f.host.identity.public_key()
        };
        assert!(
            f.sdk
                .recover_native_relay(&f.controller, &key, c, plan)
                .await
                .is_err()
        );
        h.channels.wait_stopped().await?;
        assert_eq!(
            f.sdk
                .permit(&f.permit.claims().session_id)
                .await?
                .claims()
                .connection_generation,
            1
        );
    }
    Ok(())
}
