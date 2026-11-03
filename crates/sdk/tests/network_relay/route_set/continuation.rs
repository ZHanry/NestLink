//! Real HTTP, two NodeControl owners, original business I/O and inner-TLS spare.
use super::*;
use nestlink_connectivity::continuation::{QualityConstraints, RouteIdentity};
use nestlink_remote::input::{
    InputAction, InputController, InputDevice, InputEpoch, InputEvent, InputLayout, PlatformInput,
};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Default)]
struct InputFacts {
    releases: AtomicUsize,
    resets: AtomicUsize,
    actions: AtomicUsize,
}
struct MigrationInput(Arc<InputFacts>);
impl InputDevice for MigrationInput {
    fn reset(&mut self) -> io::Result<()> {
        self.0.resets.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn inject(&mut self, input: PlatformInput<'_>) -> io::Result<()> {
        match input {
            PlatformInput::Action(_) => {
                self.0.actions.fetch_add(1, Ordering::SeqCst);
            }
            PlatformInput::Release(_) => {
                self.0.releases.fetch_add(1, Ordering::SeqCst);
            }
        }
        Ok(())
    }
}

#[tokio::test]
async fn actual_continuous_owner_prepares_and_probes_spare_without_replacing_business_and_retires_it()
-> Result {
    let mut f = Fixture::new().await?;
    let mut second = super::super::chain::ChainNode::new(&f).await?;
    let (set, _ids, controller_route) = reserve(&f, &second).await?;
    let host_key = f.host.identity.public_key();
    let controller_key = f.controller.identity.public_key();
    let host_route = f
        .sdk
        .verified_network_remote_route_set(&f.pin, &f.host, &f.permit, &controller_key, &set)
        .await?;
    let group = controller_route.transport_group();
    let bindings = controller_route.candidates().map(|c| c.route_binding());
    let active = RouteIdentity {
        transport_group: group,
        route_binding: bindings[1],
    };
    let spare = RouteIdentity {
        transport_group: group,
        route_binding: bindings[0],
    };
    let addresses = [unused_udp()?, unused_udp()?];
    let (_keep_stop, stop) = watch::channel(None);
    let (_keep_cancel, cancel) = watch::channel(false);
    let policy = AddressPolicy::new(&[])?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let (mut controller, mut host) = tokio::try_join!(
        f.sdk.connect_continuing_network_remote_route_candidate(
            controller_route,
            1,
            addresses[0],
            &f.controller,
            &host_key,
            f.setup(EndpointRole::Controller, stop.clone())?,
            &policy,
            cancel.clone(),
            deadline,
            QualityConstraints::default()
        ),
        f.sdk.connect_continuing_network_remote_route_candidate(
            host_route,
            1,
            addresses[1],
            &f.host,
            &controller_key,
            f.setup(EndpointRole::Host, stop)?,
            &policy,
            cancel,
            deadline,
            QualityConstraints::default()
        ),
    )?;
    let (sent, received) = tokio::join!(
        host.channels()
            .send(Channel::FileRead, b"original business before standby"),
        controller.channels().receive()
    );
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
    let spare_addresses = [
        controller
            .standby_local_addr()
            .ok_or("missing controller physical spare")?,
        host.standby_local_addr()
            .ok_or("missing host physical spare")?,
    ];
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
    let mut observation = controller
        .channels()
        .path_observation()
        .ok_or("missing original observation")?;
    let before = observation.timed_snapshot().map(|(at, _)| at);
    let (sent, received) = tokio::join!(
        host.channels()
            .send(Channel::FileRead, b"fresh original feedback"),
        controller.channels().receive()
    );
    sent?;
    assert_eq!(received?.payload, b"fresh original feedback");
    let (at, measured) = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(value) = observation.timed_snapshot()
                && before.is_none_or(|old| value.0 > old)
            {
                break Ok::<_, io::Error>(value);
            }
            observation.changed().await.map_err(io::Error::other)?;
        }
    })
    .await??;
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
    let (sent, received) = tokio::join!(
        host.channels().send(
            Channel::FileRead,
            b"original business after spare withdrawal"
        ),
        controller.channels().receive()
    );
    sent?;
    assert_eq!(
        received?.payload,
        b"original business after spare withdrawal"
    );
    f.sdk
        .revoke_network_remote_route_set(f.pin.space_id(), &set)
        .await?;
    tokio::try_join!(
        controller.shutdown(StopReason::Revoked),
        host.shutdown(StopReason::Revoked)
    )?;
    assert!(observation.timed_snapshot().is_none());
    let _released_active = rebind(&addresses)?;
    second.finish().await?;
    f.finish().await?;
    Ok(())
}

#[tokio::test]
async fn original_owner_authenticates_bilateral_standby_control_then_joins_safe_recovery_cleanup()
-> Result {
    let mut f = Fixture::new().await?;
    let mut second = super::super::chain::ChainNode::new(&f).await?;
    let (set, _, controller_route) = reserve(&f, &second).await?;
    let controller_key = f.controller.identity.public_key();
    let host_key = f.host.identity.public_key();
    let host_route = f
        .sdk
        .verified_network_remote_route_set(&f.pin, &f.host, &f.permit, &controller_key, &set)
        .await?;
    let (_keep_stop, stop) = watch::channel(None);
    let (_keep_cancel, cancel) = watch::channel(false);
    let policy = AddressPolicy::new(&[])?;
    let addresses = [unused_udp()?, unused_udp()?];
    let deadline = Instant::now() + Duration::from_secs(5);
    let (mut controller, mut host) = tokio::try_join!(
        f.sdk.connect_continuing_network_remote_route_candidate(
            controller_route,
            1,
            addresses[0],
            &f.controller,
            &host_key,
            f.setup(EndpointRole::Controller, stop.clone())?,
            &policy,
            cancel.clone(),
            deadline,
            QualityConstraints::default()
        ),
        f.sdk.connect_continuing_network_remote_route_candidate(
            host_route,
            1,
            addresses[1],
            &f.host,
            &controller_key,
            f.setup(EndpointRole::Host, stop)?,
            &policy,
            cancel,
            deadline,
            QualityConstraints::default()
        ),
    )?;
    tokio::try_join!(
        controller.poll(&f.sdk, &f.controller, &host_key, true),
        host.poll(&f.sdk, &f.host, &controller_key, true)
    )?;
    let standby = [
        controller
            .standby_local_addr()
            .ok_or("controller standby")?,
        host.standby_local_addr().ok_or("host standby")?,
    ];
    let (controller_receipt, host_receipt) = tokio::try_join!(
        controller.authenticate_prepared_path_recovery(&f.sdk, &f.controller, &host_key, 0, None),
        host.authenticate_prepared_path_recovery(&f.sdk, &f.host, &controller_key, 0, None),
    )?;
    assert_eq!(controller_receipt.previous_path_epoch(), 1);
    assert_eq!(controller_receipt.next_path_epoch(), 2);
    assert_eq!(host_receipt.next_path_epoch(), 2);
    assert!(controller_receipt.requires_fresh_business_admission());
    assert!(host_receipt.requires_fresh_business_admission());
    // Control permission alone does not move the original business streams.
    let (sent, received) = tokio::join!(
        host.channels()
            .send(Channel::FileRead, b"original business after signed control"),
        controller.channels().receive()
    );
    sent?;
    assert_eq!(received?.payload, b"original business after signed control");
    assert_eq!(f.control.counters()?.opened_connections, 2);
    assert_eq!(second.control.counters()?.opened_connections, 2);
    let (c, h) = tokio::try_join!(
        controller.retire_authenticated_path_recovery(
            &f.sdk,
            &f.controller,
            &host_key,
            controller_receipt
        ),
        host.retire_authenticated_path_recovery(&f.sdk, &f.host, &controller_key, host_receipt),
    )?;
    assert_eq!(c.reason, StopReason::TransportLost);
    assert_eq!(h.reason, StopReason::TransportLost);
    assert!(
        controller
            .channels()
            .send(Channel::FileRead, b"old request")
            .await
            .is_err()
    );
    drop(rebind(&addresses)?);
    drop(rebind(&standby)?);
    second.finish().await?;
    f.finish().await?;
    Ok(())
}

async fn original_inner_migration(
    single_request: bool,
    transient: bool,
    recoverable_teardown: bool,
) -> Result {
    let mut f = if transient {
        Fixture::with_permissions(
            None,
            vec![Permission::View, Permission::Input, Permission::FileRead],
        )
        .await?
    } else {
        Fixture::file_only().await?
    };
    let mut second = super::super::chain::ChainNode::new(&f).await?;
    let (set, _, controller_route) = reserve(&f, &second).await?;
    let group = controller_route.transport_group();
    let route_bindings = controller_route
        .candidates()
        .map(|candidate| candidate.route_binding());
    let controller_key = f.controller.identity.public_key();
    let host_key = f.host.identity.public_key();
    let host_route = f
        .sdk
        .verified_network_remote_route_set(&f.pin, &f.host, &f.permit, &controller_key, &set)
        .await?;
    let (_keep_stop, stop) = watch::channel(None);
    let (_keep_cancel, cancel) = watch::channel(false);
    let policy = AddressPolicy::new(&[])?;
    let addresses = [unused_udp()?, unused_udp()?];
    let deadline = Instant::now() + Duration::from_secs(5);
    let (mut controller, mut host) = tokio::try_join!(
        f.sdk.connect_continuing_network_remote_route_candidate(
            controller_route,
            1,
            addresses[0],
            &f.controller,
            &host_key,
            f.setup(EndpointRole::Controller, stop.clone())?,
            &policy,
            cancel.clone(),
            deadline,
            QualityConstraints::default(),
        ),
        f.sdk.connect_continuing_network_remote_route_candidate(
            host_route,
            1,
            addresses[1],
            &f.host,
            &controller_key,
            f.setup(EndpointRole::Host, stop)?,
            &policy,
            cancel,
            deadline,
            QualityConstraints::default(),
        ),
    )?;
    let original_controller = controller.channels().network_connection_binding()?;
    let original_host = host.channels().network_connection_binding()?;
    let original_lease_deadlines = [
        controller.channels().lease_control().current_deadline()?,
        host.channels().lease_control().current_deadline()?,
    ];
    assert_eq!(original_controller, original_host);
    let controller_observation = controller
        .channels()
        .path_observation()
        .ok_or("controller observer")?;
    let host_observation = host.channels().path_observation().ok_or("host observer")?;
    let generation = f.permit.claims().connection_generation;
    let input_facts = Arc::new(InputFacts::default());
    let input_epoch = InputEpoch {
        connection: generation,
        input: 1,
        layout: 1,
    };
    let transient_receivers = if transient {
        Some((
            controller.channels().claim_channel(Channel::Video)?,
            host.channels().claim_channel(Channel::Input)?,
        ))
    } else {
        None
    };
    let input = if transient {
        let input = InputController::attach(
            host.channels().lease_control(),
            MigrationInput(input_facts.clone()),
            input_epoch,
            InputLayout {
                left: 0,
                top: 0,
                width: 640,
                height: 480,
            },
        )?;
        assert!(input.apply(&InputEvent {
            epoch: input_epoch,
            sequence: 1,
            action: InputAction::Key {
                code: 4,
                down: true
            }
        })?);
        let old_text = InputEvent {
            epoch: input_epoch,
            sequence: 2,
            action: InputAction::Text("old queued text".into()),
        };
        controller
            .channels()
            .send(Channel::Input, &old_text.encode()?)
            .await?;
        host.channels()
            .send(Channel::Video, b"old queued reference frame")
            .await?;
        Some(input)
    } else {
        None
    };
    let payload: Vec<u8> = (0..65_536u32).map(|index| (index % 251) as u8).collect();
    for chunk in payload.chunks(nestlink_protocol::FILE_CHUNK_BYTES as usize) {
        let (sent, received) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(
                host.channels().send(Channel::FileRead, chunk),
                controller.channels().receive()
            )
        })
        .await?;
        sent?;
        assert_eq!(received?.payload, chunk);
    }
    tokio::try_join!(
        controller.poll(&f.sdk, &f.controller, &host_key, true),
        host.poll(&f.sdk, &f.host, &controller_key, true),
    )?;
    let standby = [
        controller
            .standby_local_addr()
            .ok_or("controller standby")?,
        host.standby_local_addr().ok_or("host standby")?,
    ];
    assert_eq!(controller_observation.snapshot().path_epoch, Some(1));
    if single_request {
        // The larger ordered peer asks to switch. The smaller peer alone is
        // allowed to sign Proposal, and responds through its ordinary poll.
        // It has no independently scheduled quality/failure proposal.
        if f.controller.identity.fingerprint() > f.host.identity.fingerprint() {
            let (requested, ()) = tokio::try_join!(
                controller.request_prepared_path_migration(&f.sdk, &f.controller, &host_key, 0),
                async {
                    loop {
                        let status = host
                            .poll_with_path_migration(&f.sdk, &f.host, &controller_key, true)
                            .await?;
                        if status.policy.epoch == 2 || status.policy.terminal.is_some() {
                            break Ok::<_, nestlink_sdk::native::SessionEstablishError>(());
                        }
                        assert!(status.recovery.is_none());
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                },
            )?;
            assert_eq!(requested.policy.epoch, if transient { 1 } else { 2 });
        } else {
            let (requested, ()) = tokio::try_join!(
                host.request_prepared_path_migration(&f.sdk, &f.host, &controller_key, 0),
                async {
                    loop {
                        let status = controller
                            .poll_with_path_migration(&f.sdk, &f.controller, &host_key, true)
                            .await?;
                        if status.policy.epoch == 2 || status.policy.terminal.is_some() {
                            break Ok::<_, nestlink_sdk::native::SessionEstablishError>(());
                        }
                        assert!(status.recovery.is_none());
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                },
            )?;
            assert_eq!(requested.policy.epoch, if transient { 1 } else { 2 });
        }
    } else {
        let (controller_receipt, host_receipt) = tokio::try_join!(
            controller.authenticate_prepared_path_recovery(
                &f.sdk,
                &f.controller,
                &host_key,
                0,
                None
            ),
            host.authenticate_prepared_path_recovery(&f.sdk, &f.host, &controller_key, 0, None),
        )?;
        let (controller_change, host_change) = tokio::try_join!(
            controller.commit_authenticated_path_migration(
                &f.sdk,
                &f.controller,
                &host_key,
                controller_receipt
            ),
            host.commit_authenticated_path_migration(
                &f.sdk,
                &f.host,
                &controller_key,
                host_receipt
            ),
        )?;
        for change in [&controller_change, &host_change] {
            assert_eq!(change.previous_path_epoch, 1);
            assert_eq!(change.path_epoch, 2);
            assert_eq!(change.inner_stable_id, change.original_inner_stable_id);
            assert_eq!(change.inner_tls_binding, original_controller);
            assert!(
                change.old_path_drain_limit_ms
                    <= nestlink_protocol::network_migration::MAX_DRAIN_MS
            );
        }
    }
    if transient {
        assert_eq!(input_facts.actions.load(Ordering::SeqCst), 1);
        assert_eq!(input_facts.releases.load(Ordering::SeqCst), 1);
        assert_eq!(input_facts.resets.load(Ordering::SeqCst), 1);
        let input = input.ok_or("missing original input owner")?;
        assert!(
            input
                .apply(&InputEvent {
                    epoch: input_epoch,
                    sequence: 2,
                    action: InputAction::Text("old queued text".into())
                })
                .is_err()
        );
        let (mut video, mut old_input) = transient_receivers.ok_or("missing old channel claims")?;
        assert!(video.receive().await.is_err());
        assert!(old_input.receive().await.is_err());
        assert!(
            host.channels()
                .send(Channel::FileRead, b"old business after teardown")
                .await
                .is_err()
        );
        assert_eq!(
            controller
                .channels()
                .lease_control()
                .subscribe_stopped()
                .borrow()
                .as_ref()
                .map(|report| report.reason),
            Some(StopReason::TransportLost)
        );
        assert_eq!(
            host.channels()
                .lease_control()
                .subscribe_stopped()
                .borrow()
                .as_ref()
                .map(|report| report.reason),
            Some(StopReason::TransportLost)
        );
        assert_eq!(controller_observation.snapshot().path_epoch, Some(1));
        assert!(controller_observation.snapshot().stopped);
        assert!(host_observation.snapshot().stopped);
        drop(rebind(&addresses)?);
        drop(rebind(&standby)?);
        second.finish().await?;
        f.finish().await?;
        return Ok(());
    }
    assert_eq!(
        controller.channels().network_connection_binding()?,
        original_controller
    );
    assert_eq!(host.channels().network_connection_binding()?, original_host);
    for observation in [&controller_observation, &host_observation] {
        let snapshot = observation.snapshot();
        assert_eq!(snapshot.path_epoch, Some(2));
        assert_eq!(snapshot.binding.route_binding, Some(route_bindings[0]));
        assert_eq!(snapshot.binding.business_generation, generation);
        assert_eq!(snapshot.binding.transport_group, Some(group));
        // Old ACK/counter windows cannot change their route label at commit.
        assert_eq!(snapshot.rtt, None);
        assert_eq!(snapshot.business_tx, None);
        assert_eq!(snapshot.packet_loss, None);
    }
    drop(rebind(&addresses)?);
    assert_eq!(controller.status()?.policy.epoch, 2);
    assert_eq!(host.status()?.policy.epoch, 2);
    assert_eq!(controller.status()?.policy.pending_retirements, 0);
    assert_eq!(host.status()?.policy.pending_retirements, 0);
    assert_eq!(f.control.counters()?.opened_connections, 2);
    assert_eq!(second.control.counters()?.opened_connections, 2);
    // The same original observer must follow the actual committed owner.
    // Withdrawal of the fully released old member cannot revoke the healthy
    // new member, while its immutable signed group remains unchanged.
    f.sdk.revoke_node(&second.id).await?;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    for chunk in payload.chunks(nestlink_protocol::FILE_CHUNK_BYTES as usize) {
        let (sent, received) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(
                host.channels().send(Channel::FileRead, chunk),
                controller.channels().receive()
            )
        })
        .await?;
        sent?;
        assert_eq!(received?.payload, chunk);
    }
    if recoverable_teardown {
        let (controller_report, host_report) = tokio::try_join!(
            controller.shutdown(StopReason::TransportLost),
            host.shutdown(StopReason::TransportLost),
        )?;
        assert_eq!(controller_report.reason, StopReason::TransportLost);
        assert_eq!(host_report.reason, StopReason::TransportLost);
        // These budgets follow actual current/old carrier and guardian joins.
        // A late guardian Drop must not turn their recoverable retirement
        // into PermissionDenied or extend the original signed deadline.
        for (budget, original_deadline) in [
            controller
                .channels()
                .lease_control()
                .reconnection_budget()?,
            host.channels().lease_control().reconnection_budget()?,
        ]
        .into_iter()
        .zip(original_lease_deadlines)
        {
            assert_eq!(budget.permit().digest(), f.permit.digest());
            assert_eq!(budget.deadline(), original_deadline);
            assert!(budget.deadline() > Instant::now().into_std());
        }
        f.sdk
            .revoke_network_remote_route_set(f.pin.space_id(), &set)
            .await?;
    } else {
        f.sdk
            .revoke_network_remote_route_set(f.pin.space_id(), &set)
            .await?;
        tokio::try_join!(
            controller.shutdown(StopReason::Revoked),
            host.shutdown(StopReason::Revoked)
        )?;
    }
    drop(rebind(&standby)?);
    assert!(controller_observation.snapshot().stopped);
    assert!(host_observation.snapshot().stopped);
    second.finish_revoked().await?;
    f.finish().await?;
    Ok(())
}

#[tokio::test]
async fn signed_migration_keeps_original_inner_and_business_stream_after_old_carrier_release()
-> Result {
    original_inner_migration(false, false, false).await
}

#[tokio::test]
async fn one_endpoint_requests_migration_and_the_other_poll_responds_with_the_unique_signed_proposer()
-> Result {
    original_inner_migration(true, false, false).await
}

#[tokio::test]
async fn input_and_video_use_bilateral_safe_recovery_with_real_release_and_no_old_queue_delivery()
-> Result {
    original_inner_migration(true, true, false).await
}

#[tokio::test]
async fn migrated_file_owner_keeps_safe_recovery_budget_after_transport_loss_and_guardian_cleanup()
-> Result {
    original_inner_migration(false, false, true).await
}
