//! Signed permits and a real proved InputController; no fake authorization.
use super::super::input::{InputPermitResolver, InputPermitWindows, ResolvedInput};
use super::*;

struct InputFixture {
    signer: PermitSigner,
    permit: VerifiedPermit,
    lease: LeaseControl,
    clock: RuntimeClock,
    controller: InputController<RecordingInputDevice>,
    records: Arc<std::sync::Mutex<Vec<RecordedInput>>>,
    windows: watch::Sender<Option<InputPermitWindows>>,
    cancel: watch::Sender<bool>,
    _stop_owner: watch::Sender<Option<StopReason>>,
    resolver: InputPermitResolver,
}

impl InputFixture {
    fn new(retained_budget: Option<Duration>) -> TestResult<Self> {
        let controller_identity = DeviceIdentity::generate();
        let host = DeviceIdentity::generate();
        let prototype = test_permit_with_permissions(
            &controller_identity,
            &host,
            vec![Permission::View, Permission::Input],
        )?;
        let signer = PermitSigner::generate();
        let permit = signed_input_permit(&signer, prototype.claims())?;
        let (mut setup, stop_owner) = test_setup(&permit, EndpointRole::Host)?;
        if let Some(budget) = retained_budget {
            setup
                .session
                .cap_deadline_ms(setup.clock.monotonic_ms() + u64::try_from(budget.as_millis())?)?;
        }
        let transcript = setup.session.proof_transcript();
        for (role, identity) in [
            (EndpointRole::Controller, &controller_identity),
            (EndpointRole::Host, &host),
        ] {
            setup.session.confirm_endpoint(
                role,
                &identity.identity.public_key(),
                &identity.identity.prove(&transcript)?,
                setup.clock.monotonic_ms(),
            )?;
        }
        let clock = setup.clock.clone();
        let lease = LeaseControl::from_proved_session(
            setup.session,
            setup.path,
            setup.clock,
            setup.lifecycle,
        )?;
        let epoch = InputEpoch {
            input: 1,
            layout: 1,
            connection: 1,
        };
        let layout = InputLayout {
            left: -1920,
            top: 0,
            width: 1920,
            height: 1080,
        };
        let records = Arc::new(std::sync::Mutex::new(Vec::new()));
        let controller = InputController::attach(
            lease.clone(),
            RecordingInputDevice(records.clone()),
            epoch,
            layout,
        )?;
        let windows =
            InputPermitWindows::new(permit.clone(), lease.input_permit_deadline(&permit)?)?;
        let (windows, receiver) = watch::channel(Some(windows));
        let (cancel, cancellation) = watch::channel(false);
        let resolver = InputPermitResolver::new(
            receiver,
            cancellation,
            lease.subscribe_stopped(),
            clock.clone(),
        );
        Ok(Self {
            signer,
            permit,
            lease,
            clock,
            controller,
            records,
            windows,
            cancel,
            _stop_owner: stop_owner,
            resolver,
        })
    }

    fn next(&self, previous: &VerifiedPermit) -> TestResult<VerifiedPermit> {
        let mut claims = previous.claims().clone();
        claims.lease_sequence += 1;
        claims.issued_at_unix_ms = unix_ms()?.max(claims.issued_at_unix_ms);
        claims.expires_at_unix_ms = claims.issued_at_unix_ms + nestlink_protocol::SESSION_LEASE_MS;
        signed_input_permit(&self.signer, &claims)
    }

    fn apply(&mut self, resolved: ResolvedInput) -> TestResult<bool> {
        resolved.guard.check()?;
        let (deadline, expires_at_unix_ms) = resolved.guard.original_deadlines();
        let WebRtcControl::InputEvent {
            input_epoch,
            layout_epoch,
            connection_generation,
            lease_sequence,
            sequence,
            action,
            ..
        } = resolved.control
        else {
            return Err(io::Error::other("expected an input event").into());
        };
        let action = match action {
            WebRtcInputAction::Key { usage, down } => InputAction::Key { code: usage, down },
            WebRtcInputAction::Pointer { button, down, x, y } => {
                InputAction::Pointer { button, down, x, y }
            }
            WebRtcInputAction::Scroll { x, y } => InputAction::Scroll { x, y },
            WebRtcInputAction::Text { text } => InputAction::Text(text),
        };
        let applied = self.controller.apply_with_deadline(
            &InputEvent {
                epoch: InputEpoch {
                    input: input_epoch,
                    layout: layout_epoch,
                    connection: connection_generation,
                },
                sequence,
                action,
            },
            deadline,
            expires_at_unix_ms,
        )?;
        self.resolver.input_event_applied(lease_sequence);
        Ok(applied)
    }

    fn actions(&self) -> TestResult<usize> {
        Ok(self
            .records
            .lock()
            .map_err(|_| io::Error::other("input records poisoned"))?
            .iter()
            .filter(|item| matches!(item, RecordedInput::Action(_)))
            .count())
    }
}

fn signed_input_permit(signer: &PermitSigner, claims: &PermitClaims) -> TestResult<VerifiedPermit> {
    Ok(verify_permit(
        &signer.sign(claims)?.encode_to_vec(),
        &signer.public_key(),
    )?)
}

fn input_message(permit: &VerifiedPermit, sequence: u64) -> TestResult<Vec<u8>> {
    Ok(WebRtcControl::InputEvent {
        schema_version: SCHEMA_VERSION,
        session_id: permit.claims().session_id.clone(),
        connection_generation: permit.claims().connection_generation,
        lease_sequence: permit.claims().lease_sequence,
        input_epoch: 1,
        layout_epoch: 1,
        sequence,
        action: WebRtcInputAction::Pointer {
            button: Some(1),
            down: !sequence.is_multiple_of(2),
            x: -960,
            y: 540,
        },
    }
    .encode_validated(permit.claims())?)
}

async fn install_input_permit(
    lease: &LeaseControl,
    clock: &RuntimeClock,
    windows: &watch::Sender<Option<InputPermitWindows>>,
    permit: &VerifiedPermit,
) -> TestResult {
    // Each request starts strictly after the previous real lease request clock.
    tokio::time::sleep(Duration::from_millis(3)).await;
    lease.renew(permit.clone(), clock.monotonic_ms())?;
    let deadline = lease.input_permit_deadline(permit)?;
    let previous = windows
        .borrow()
        .clone()
        .ok_or_else(|| io::Error::other("input windows missing"))?;
    windows.send_replace(Some(previous.advance(permit.clone(), deadline)?));
    Ok(())
}

#[tokio::test]
async fn next_input_waits_for_real_lease_renewal_before_injecting() -> TestResult {
    let mut f = InputFixture::new(None)?;
    let next = f.next(&f.permit)?;
    let bytes = input_message(&next, 1)?;
    assert!(f.lease.input_permit_deadline(&next).is_err());
    let mut waiting = Box::pin(f.resolver.resolve(&bytes));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut waiting)
            .await
            .is_err()
    );
    assert!(
        f.records
            .lock()
            .map_err(|_| io::Error::other("records poisoned"))?
            .is_empty()
    );
    install_input_permit(&f.lease, &f.clock, &f.windows, &next).await?;
    let resolved = waiting.await?;
    assert!(f.apply(resolved)?);
    assert_eq!(f.actions()?, 1);
    Ok(())
}

#[tokio::test]
async fn host_refresh_before_old_packet_arrival_keeps_original_valid_window() -> TestResult {
    let mut f = InputFixture::new(None)?;
    let old = f.permit.clone();
    let next = f.next(&old)?;
    let old_deadline = f.lease.input_permit_deadline(&old)?;
    install_input_permit(&f.lease, &f.clock, &f.windows, &next).await?;
    assert!(f.lease.input_permit_deadline(&old).is_err());
    // These bytes arrive only after host publication advanced to sequence two.
    let resolved = f.resolver.resolve(&input_message(&old, 1)?).await?;
    assert!(f.apply(resolved)?);
    let resolved = f.resolver.resolve(&input_message(&next, 2)?).await?;
    assert!(f.apply(resolved)?);
    // A bigger global input sequence cannot resurrect the retired old lease.
    assert!(
        f.resolver
            .resolve(&input_message(&old, 100)?)
            .await
            .is_err()
    );
    assert!(old_deadline > Instant::now());
    assert_eq!(f.actions()?, 2);
    Ok(())
}

#[tokio::test]
async fn resolved_old_packet_survives_refresh_without_an_arrival_snapshot() -> TestResult {
    let mut f = InputFixture::new(None)?;
    let old = f.permit.clone();
    let queued = f.resolver.resolve(&input_message(&old, 1)?).await?;
    let next = f.next(&old)?;
    install_input_permit(&f.lease, &f.clock, &f.windows, &next).await?;
    assert!(f.apply(queued)?);
    assert_eq!(f.actions()?, 1);
    Ok(())
}

#[tokio::test]
async fn renewal_does_not_reset_the_input_controller_replay_sequence() -> TestResult {
    let mut f = InputFixture::new(None)?;
    let old = f.permit.clone();
    let event = input_message(&old, 1)?;
    let resolved = f.resolver.resolve(&event).await?;
    assert!(f.apply(resolved)?);
    let resolved = f.resolver.resolve(&event).await?;
    assert!(!f.apply(resolved)?);
    let next = f.next(&old)?;
    install_input_permit(&f.lease, &f.clock, &f.windows, &next).await?;
    let resolved = f.resolver.resolve(&input_message(&next, 1)?).await?;
    assert!(!f.apply(resolved)?);
    let mut changed: WebRtcControl = serde_json::from_slice(&input_message(&next, 1)?)?;
    if let WebRtcControl::InputEvent { action, .. } = &mut changed {
        *action = WebRtcInputAction::Key {
            usage: 4,
            down: true,
        };
    }
    let resolved = f
        .resolver
        .resolve(&changed.encode_validated(next.claims())?)
        .await?;
    assert!(f.apply(resolved).is_err());
    assert_eq!(f.actions()?, 1);
    Ok(())
}

#[tokio::test]
async fn previous_original_monotonic_deadline_is_not_extended_by_renewal() -> TestResult {
    let mut f = InputFixture::new(Some(Duration::from_millis(500)))?;
    let old = f.permit.clone();
    let deadline = f.lease.input_permit_deadline(&old)?;
    let next = f.next(&old)?;
    install_input_permit(&f.lease, &f.clock, &f.windows, &next).await?;
    let queued = f.resolver.resolve(&input_message(&old, 1)?).await?;
    tokio::time::sleep(
        deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(5),
    )
    .await;
    assert!(unix_ms()? < old.claims().expires_at_unix_ms);
    assert!(f.lease.input_permit_deadline(&next).is_ok());
    assert!(queued.guard.check().is_err());
    assert!(f.resolver.resolve(&input_message(&old, 1)?).await.is_err());
    assert_eq!(f.actions()?, 0);
    Ok(())
}

#[tokio::test]
async fn expired_previous_release_is_rejected_and_held_buttons_use_normal_cleanup() -> TestResult {
    let mut f = InputFixture::new(Some(Duration::from_millis(500)))?;
    let old = f.permit.clone();
    let resolved = f.resolver.resolve(&input_message(&old, 1)?).await?;
    assert!(f.apply(resolved)?);
    let next = f.next(&old)?;
    install_input_permit(&f.lease, &f.clock, &f.windows, &next).await?;
    let release = WebRtcControl::InputReleaseAll {
        schema_version: SCHEMA_VERSION,
        session_id: old.claims().session_id.clone(),
        connection_generation: old.claims().connection_generation,
        lease_sequence: old.claims().lease_sequence,
        input_epoch: 1,
        layout_epoch: 1,
    }
    .encode_validated(old.claims())?;
    let queued = f.resolver.resolve(&release).await?;
    queued.guard.check()?;
    let (deadline, wall_expiry) = queued.guard.original_deadlines();
    tokio::time::sleep(
        deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(5),
    )
    .await;
    assert!(f.lease.input_permit_deadline(&next).is_ok());
    assert!(
        f.controller
            .release_all_with_deadline(
                InputEpoch {
                    input: 1,
                    layout: 1,
                    connection: 1
                },
                deadline,
                wall_expiry,
            )
            .is_err()
    );
    // The expired envelope does not gain current authority. The established
    // release failure path still stops the lease and releases its held button.
    let stopped = f
        .lease
        .subscribe_stopped()
        .borrow()
        .ok_or_else(|| io::Error::other("release did not stop"))?;
    assert_eq!(stopped.reason, StopReason::Revoked);
    assert_eq!(stopped.cleanup, CleanupStatus::Succeeded);
    assert_eq!(f.actions()?, 1);
    assert_eq!(
        f.records
            .lock()
            .map_err(|_| io::Error::other("records poisoned"))?
            .iter()
            .filter(|item| matches!(item, RecordedInput::Release(_)))
            .count(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn previous_wall_expiry_is_checked_even_with_a_longer_retained_deadline() -> TestResult {
    let mut f = InputFixture::new(None)?;
    let mut old_claims = f.permit.claims().clone();
    let wall_now = unix_ms()?;
    old_claims.issued_at_unix_ms = wall_now - nestlink_protocol::SESSION_LEASE_MS;
    old_claims.expires_at_unix_ms = wall_now - 1;
    let old = signed_input_permit(&f.signer, &old_claims)?;
    let mut next_claims = f.permit.claims().clone();
    next_claims.lease_sequence = 2;
    let next = signed_input_permit(&f.signer, &next_claims)?;
    // Defensive decoding test: even an inconsistent overlong history deadline
    // cannot make the genuinely expired signed permit usable.
    let windows = InputPermitWindows::new(old.clone(), Instant::now() + Duration::from_secs(10))?
        .advance(next, Instant::now() + Duration::from_secs(10))?;
    f.windows.send_replace(Some(windows));
    assert!(f.resolver.resolve(&input_message(&old, 1)?).await.is_err());
    assert_eq!(f.actions()?, 0);
    Ok(())
}

#[tokio::test]
async fn waiting_input_cancels_without_installing_or_applying_a_permit() -> TestResult {
    let mut f = InputFixture::new(None)?;
    let next = f.next(&f.permit)?;
    let bytes = input_message(&next, 1)?;
    let mut waiting = Box::pin(f.resolver.resolve(&bytes));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut waiting)
            .await
            .is_err()
    );
    f.cancel.send_replace(true);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), waiting)
            .await?
            .is_err()
    );
    assert_eq!(f.actions()?, 0);
    assert!(f.lease.input_permit_deadline(&next).is_err());
    Ok(())
}

#[tokio::test]
async fn waiting_input_stops_on_current_lease_revocation() -> TestResult {
    let mut f = InputFixture::new(None)?;
    let next = f.next(&f.permit)?;
    let bytes = input_message(&next, 1)?;
    let mut waiting = Box::pin(f.resolver.resolve(&bytes));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut waiting)
            .await
            .is_err()
    );
    f.lease.stop(StopReason::Revoked)?;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), waiting)
            .await?
            .is_err()
    );
    assert_eq!(f.actions()?, 0);
    Ok(())
}

#[tokio::test]
async fn closed_permit_watch_rejects_even_its_retained_value() -> TestResult {
    let mut f = InputFixture::new(None)?;
    let bytes = input_message(&f.permit, 1)?;
    drop(f.windows);
    assert!(f.resolver.resolve(&bytes).await.is_err());
    Ok(())
}

#[tokio::test]
async fn waiting_input_fails_when_the_permit_publisher_closes() -> TestResult {
    let mut f = InputFixture::new(None)?;
    let next = f.next(&f.permit)?;
    let bytes = input_message(&next, 1)?;
    let mut waiting = Box::pin(f.resolver.resolve(&bytes));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut waiting)
            .await
            .is_err()
    );
    drop(f.windows);
    assert!(
        tokio::time::timeout(Duration::from_millis(500), waiting)
            .await?
            .is_err()
    );
    assert!(
        !f.records
            .lock()
            .map_err(|_| io::Error::other("records poisoned"))?
            .iter()
            .any(|item| matches!(item, RecordedInput::Action(_)))
    );
    Ok(())
}

#[tokio::test]
async fn waiting_input_fails_when_the_cancel_publisher_closes() -> TestResult {
    let mut f = InputFixture::new(None)?;
    let next = f.next(&f.permit)?;
    let bytes = input_message(&next, 1)?;
    let mut waiting = Box::pin(f.resolver.resolve(&bytes));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut waiting)
            .await
            .is_err()
    );
    drop(f.cancel);
    assert!(
        tokio::time::timeout(Duration::from_millis(500), waiting)
            .await?
            .is_err()
    );
    assert!(
        !f.records
            .lock()
            .map_err(|_| io::Error::other("records poisoned"))?
            .iter()
            .any(|item| matches!(item, RecordedInput::Action(_)))
    );
    Ok(())
}

#[tokio::test]
async fn waiting_input_fails_when_the_stopped_publisher_closes() -> TestResult {
    let f = InputFixture::new(None)?;
    let next = f.next(&f.permit)?;
    let bytes = input_message(&next, 1)?;
    // Only the notification owner is replaced to exercise closed-watch handling;
    // the real proved lease and attached input controller still own authority.
    let (stop_publisher, stopped) = watch::channel(None);
    let mut resolver = InputPermitResolver::new(
        f.windows.subscribe(),
        f.cancel.subscribe(),
        stopped,
        f.clock.clone(),
    );
    let mut waiting = Box::pin(resolver.resolve(&bytes));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut waiting)
            .await
            .is_err()
    );
    drop(stop_publisher);
    assert!(
        tokio::time::timeout(Duration::from_millis(500), waiting)
            .await?
            .is_err()
    );
    assert_eq!(f.actions()?, 0);
    Ok(())
}

#[tokio::test]
async fn waiting_input_cannot_outlive_the_current_original_deadline() -> TestResult {
    let mut f = InputFixture::new(Some(Duration::from_millis(500)))?;
    let current = f.permit.clone();
    let original = f.lease.input_permit_deadline(&current)?;
    let next = f.next(&current)?;
    let bytes = input_message(&next, 1)?;
    assert!(
        tokio::time::timeout(Duration::from_secs(1), f.resolver.resolve(&bytes),)
            .await?
            .is_err()
    );
    assert!(Instant::now() >= original);
    assert!(unix_ms()? < current.claims().expires_at_unix_ms);
    assert_eq!(f.actions()?, 0);
    assert!(f.lease.input_permit_deadline(&next).is_err());
    Ok(())
}

#[tokio::test]
async fn next_without_signed_refresh_times_out_with_zero_injection() -> TestResult {
    let mut f = InputFixture::new(None)?;
    let next = f.next(&f.permit)?;
    assert!(
        tokio::time::timeout(
            Duration::from_secs(3),
            f.resolver.resolve(&input_message(&next, 1)?),
        )
        .await?
        .is_err()
    );
    assert_eq!(f.actions()?, 0);
    assert!(f.lease.input_permit_deadline(&next).is_err());
    Ok(())
}

#[tokio::test]
async fn delayed_poll_cannot_accept_next_permit_after_original_wait_budget() -> TestResult {
    let mut f = InputFixture::new(None)?;
    let next = f.next(&f.permit)?;
    let bytes = input_message(&next, 1)?;
    let mut waiting = Box::pin(f.resolver.resolve(&bytes));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut waiting)
            .await
            .is_err()
    );
    // Do not poll this owned resolver while its fixed timer expires. Both the
    // signed publication and its timer are ready when it next gets CPU time.
    tokio::time::sleep(Duration::from_millis(2_100)).await;
    install_input_permit(&f.lease, &f.clock, &f.windows, &next).await?;
    assert!(
        waiting.await.is_err(),
        "next permit was accepted after the original two-second wait budget"
    );
    assert_eq!(f.actions()?, 0);
    assert!(f.lease.input_permit_deadline(&next).is_ok());
    Ok(())
}

#[tokio::test]
async fn delayed_poll_cannot_extend_wait_past_original_authority_deadline() -> TestResult {
    let mut f = InputFixture::new(Some(Duration::from_millis(500)))?;
    let original = f.lease.input_permit_deadline(&f.permit)?;
    let next = f.next(&f.permit)?;
    let bytes = input_message(&next, 1)?;
    let mut waiting = Box::pin(f.resolver.resolve(&bytes));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut waiting)
            .await
            .is_err()
    );
    install_input_permit(&f.lease, &f.clock, &f.windows, &next).await?;
    // Renewal succeeds while the old lease is live, but this pending input is
    // not polled again until its original, narrower waiting horizon expires.
    tokio::time::sleep(
        original.saturating_duration_since(Instant::now()) + Duration::from_millis(5),
    )
    .await;
    assert!(waiting.await.is_err());
    assert!(f.lease.input_permit_deadline(&next).is_ok());
    assert_eq!(f.actions()?, 0);
    Ok(())
}

#[tokio::test]
async fn malformed_next_epoch_and_action_cannot_wait_without_a_bound() -> TestResult {
    for case in 0..2 {
        let mut f = InputFixture::new(None)?;
        let next = f.next(&f.permit)?;
        let mut control: WebRtcControl = serde_json::from_slice(&input_message(&next, 1)?)?;
        if let WebRtcControl::InputEvent {
            input_epoch,
            action,
            ..
        } = &mut control
        {
            if case == 0 {
                *input_epoch = 0;
            } else {
                *action = WebRtcInputAction::Pointer {
                    button: None,
                    down: true,
                    x: -960,
                    y: 540,
                };
            }
        }
        let bytes = serde_json::to_vec(&control)?;
        assert!(
            tokio::time::timeout(Duration::from_secs(3), f.resolver.resolve(&bytes),)
                .await?
                .is_err()
        );
        assert_eq!(f.actions()?, 0);
        assert!(f.lease.input_permit_deadline(&next).is_err());
    }
    Ok(())
}

#[tokio::test]
async fn wrong_live_input_or_layout_epoch_remains_rejected_after_signed_refresh() -> TestResult {
    for case in 0..2 {
        let mut f = InputFixture::new(None)?;
        let next = f.next(&f.permit)?;
        let mut control: WebRtcControl = serde_json::from_slice(&input_message(&next, 1)?)?;
        if let WebRtcControl::InputEvent {
            input_epoch,
            layout_epoch,
            ..
        } = &mut control
        {
            if case == 0 {
                *input_epoch = 2;
            } else {
                *layout_epoch = 2;
            }
        }
        let bytes = control.encode_validated(next.claims())?;
        let mut waiting = Box::pin(f.resolver.resolve(&bytes));
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut waiting)
                .await
                .is_err()
        );
        install_input_permit(&f.lease, &f.clock, &f.windows, &next).await?;
        let resolved = tokio::time::timeout(Duration::from_millis(500), waiting).await??;
        assert!(f.apply(resolved).is_err());
        assert_eq!(f.actions()?, 0);
    }
    Ok(())
}

#[tokio::test]
async fn forged_binding_and_skipped_lease_fail_before_waiting() -> TestResult {
    let mut f = InputFixture::new(None)?;
    let mut messages = Vec::new();
    let next = f.next(&f.permit)?;
    for case in 0..3 {
        let mut message: WebRtcControl = serde_json::from_slice(&input_message(&next, 1)?)?;
        if let WebRtcControl::InputEvent {
            session_id,
            connection_generation,
            lease_sequence,
            ..
        } = &mut message
        {
            match case {
                0 => *session_id = id(99),
                1 => *connection_generation += 1,
                _ => *lease_sequence += 1,
            }
        }
        messages.push(serde_json::to_vec(&message)?);
    }
    for bytes in messages {
        assert!(
            tokio::time::timeout(Duration::from_millis(100), f.resolver.resolve(&bytes))
                .await?
                .is_err()
        );
    }
    assert_eq!(f.actions()?, 0);
    Ok(())
}

#[tokio::test]
async fn signed_but_changed_authorization_cannot_enter_input_history() -> TestResult {
    let f = InputFixture::new(None)?;
    let next = f.next(&f.permit)?;
    let windows = f
        .windows
        .borrow()
        .clone()
        .ok_or_else(|| io::Error::other("windows missing"))?;
    for case in 0..5 {
        let mut claims = next.claims().clone();
        match case {
            0 => claims.security_epoch += 1,
            1 => claims.connection_generation += 1,
            2 => claims.policy_revision += 1,
            3 => claims.permissions = vec![Permission::View as i32],
            _ => claims.paths = vec![Path::Relay as i32],
        }
        let changed = signed_input_permit(&f.signer, &claims)?;
        assert!(
            windows
                .advance(changed, Instant::now() + Duration::from_secs(15))
                .is_err()
        );
    }
    let wrong_issuer = PermitSigner::generate();
    let changed = signed_input_permit(&wrong_issuer, next.claims())?;
    assert!(
        windows
            .advance(changed, Instant::now() + Duration::from_secs(15))
            .is_err()
    );
    assert!(
        verify_permit(
            &f.signer.sign(next.claims())?.encode_to_vec(),
            &wrong_issuer.public_key()
        )
        .is_err()
    );
    assert!(f.lease.input_permit_deadline(&next).is_err());
    Ok(())
}

#[tokio::test]
async fn current_authority_and_expiry_are_rechecked_before_actual_application() -> TestResult {
    let mut f = InputFixture::new(None)?;
    let current = f.permit.clone();
    let resolved = f.resolver.resolve(&input_message(&current, 1)?).await?;
    f.cancel.send_replace(true);
    assert!(resolved.guard.check().is_err());
    f.cancel.send_replace(false);
    let resolved = f.resolver.resolve(&input_message(&current, 1)?).await?;
    f.lease.stop(StopReason::Revoked)?;
    assert!(resolved.guard.check().is_err());
    assert!(f.apply(resolved).is_err());
    assert_eq!(f.actions()?, 0);
    Ok(())
}

#[tokio::test]
async fn multiple_renewals_evict_old_windows_and_preserve_sequence_retirement() -> TestResult {
    let mut f = InputFixture::new(None)?;
    let one = f.permit.clone();
    let two = f.next(&one)?;
    install_input_permit(&f.lease, &f.clock, &f.windows, &two).await?;
    let resolved = f.resolver.resolve(&input_message(&two, 1)?).await?;
    assert!(f.apply(resolved)?);
    let three = f.next(&two)?;
    install_input_permit(&f.lease, &f.clock, &f.windows, &three).await?;
    assert!(
        f.resolver
            .resolve(&input_message(&one, 200)?)
            .await
            .is_err()
    );
    let resolved = f.resolver.resolve(&input_message(&two, 2)?).await?;
    assert!(f.apply(resolved)?);
    let resolved = f.resolver.resolve(&input_message(&three, 3)?).await?;
    assert!(f.apply(resolved)?);
    assert!(
        f.resolver
            .resolve(&input_message(&two, 201)?)
            .await
            .is_err()
    );
    assert_eq!(f.actions()?, 3);
    Ok(())
}

#[tokio::test]
async fn repeated_same_permit_publication_does_not_extend_the_original_deadline() -> TestResult {
    let mut f = InputFixture::new(Some(Duration::from_millis(500)))?;
    let current = f.permit.clone();
    let original = f.lease.input_permit_deadline(&current)?;
    let windows = f
        .windows
        .borrow()
        .clone()
        .ok_or_else(|| io::Error::other("windows missing"))?;
    f.windows.send_replace(Some(
        windows.advance(current.clone(), Instant::now() + Duration::from_secs(30))?,
    ));
    tokio::time::sleep(
        original.saturating_duration_since(Instant::now()) + Duration::from_millis(5),
    )
    .await;
    assert!(
        f.resolver
            .resolve(&input_message(&current, 1)?)
            .await
            .is_err()
    );
    assert_eq!(f.actions()?, 0);
    Ok(())
}

#[tokio::test]
async fn narrow_deadline_query_requires_input_and_a_live_matching_permit() -> TestResult {
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    let view = test_permit(&controller, &host)?;
    let (lease, _owner) = test_proved_lease(&view, &controller, &host)?;
    assert!(lease.input_permit_deadline(&view).is_err());
    let f = InputFixture::new(None)?;
    assert!(f.lease.input_permit_deadline(&f.permit).is_ok());
    let next = f.next(&f.permit)?;
    assert!(f.lease.input_permit_deadline(&next).is_err());
    f.lease.stop(StopReason::Revoked)?;
    assert!(f.lease.input_permit_deadline(&f.permit).is_err());
    Ok(())
}
