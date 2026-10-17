#![cfg(not(target_arch = "wasm32"))]
#[path = "clipboard/support.rs"]
mod support;
use nestlink_protocol::{
    ClipboardErrorCode, ClipboardWriteEffect, NativeClipboard, Permission, SCHEMA_VERSION,
    native_clipboard::Action,
};
use nestlink_remote::{
    RemoteError,
    clipboard::{
        ClaimedClipboardTransport, ClipboardBinding, ClipboardConsent, ClipboardDevice,
        ClipboardDirection, ClipboardDirections, ClipboardServer, ClipboardShutdown,
        ClipboardWriteOutcome,
    },
};
use nestlink_sdk::clipboard::{
    NativeClipboardError, NativeClipboardOutput, NativeClipboardOwner, NativeClipboardPayload,
    NativeClipboardShutdown,
};
use nestlink_session::StopReason;
use nestlink_transport_stream::Channel;
use std::{
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use support::{Result, Sessions};
use zeroize::Zeroizing;
const BOTH: ClipboardDirections = ClipboardDirections {
    read: true,
    write: true,
};
struct Consent(Arc<AtomicBool>);
impl ClipboardConsent for Consent {
    fn check_until(&self, deadline: Instant) -> io::Result<()> {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        if self.0.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(io::ErrorKind::PermissionDenied.into())
        }
    }
}
#[derive(Default)]
struct Gate {
    entered: AtomicBool,
    released: AtomicBool,
}
impl Gate {
    fn wait(&self) {
        self.entered.store(true, Ordering::Release);
        while !self.released.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn release(&self) {
        self.released.store(true, Ordering::Release);
    }
}
impl Drop for Gate {
    fn drop(&mut self) {
        self.release();
    }
}
struct State {
    text: Mutex<Option<String>>,
    read: Arc<AtomicBool>,
    write: Arc<AtomicBool>,
    reads: AtomicUsize,
    writes: AtomicUsize,
    read_gate: Option<Arc<Gate>>,
    write_gate: Option<Arc<Gate>>,
    unknown_write: bool,
    closed: AtomicBool,
}
impl State {
    fn new(
        read_gate: Option<Arc<Gate>>,
        write_gate: Option<Arc<Gate>>,
        unknown_write: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            text: Mutex::new(Some("原始中文\ntext".into())),
            read: Arc::new(AtomicBool::new(true)),
            write: Arc::new(AtomicBool::new(true)),
            reads: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
            read_gate,
            write_gate,
            unknown_write,
            closed: AtomicBool::new(false),
        })
    }
}
struct Device {
    binding: ClipboardBinding,
    state: Arc<State>,
}
impl ClipboardDevice for Device {
    fn binding(&self) -> &ClipboardBinding {
        &self.binding
    }
    fn consent(&self, direction: ClipboardDirection) -> Arc<dyn ClipboardConsent> {
        Arc::new(Consent(match direction {
            ClipboardDirection::Read => self.state.read.clone(),
            ClipboardDirection::Write => self.state.write.clone(),
        }))
    }
    fn read_text(
        &mut self,
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Option<String>> {
        check()?;
        self.state.reads.fetch_add(1, Ordering::AcqRel);
        let text = self
            .state
            .text
            .lock()
            .map_err(|_| io::Error::other("fixture text poisoned"))?
            .clone()
            .map(Zeroizing::new);
        if let Some(gate) = &self.state.read_gate {
            gate.wait();
        }
        check()?;
        Ok(text.map(|mut text| std::mem::take(&mut *text)))
    }
    fn write_text(
        &mut self,
        text: &str,
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> ClipboardWriteOutcome {
        if let Err(error) = check() {
            return ClipboardWriteOutcome {
                effect: ClipboardWriteEffect::ClipboardWriteNotApplied,
                error: Some(error),
            };
        }
        if let Ok(mut stored) = self.state.text.lock() {
            *stored = Some(text.into());
        }
        self.state.writes.fetch_add(1, Ordering::AcqRel);
        if let Some(gate) = &self.state.write_gate {
            gate.wait();
        }
        if self.state.unknown_write {
            ClipboardWriteOutcome {
                effect: ClipboardWriteEffect::ClipboardWriteUnknown,
                error: Some(io::ErrorKind::Other.into()),
            }
        } else {
            ClipboardWriteOutcome {
                effect: ClipboardWriteEffect::ClipboardWriteApplied,
                error: check().err(),
            }
        }
    }
    fn close(&mut self) -> io::Result<()> {
        self.state.closed.store(true, Ordering::Release);
        Ok(())
    }
    fn cleanup_complete(&self) -> bool {
        self.state.closed.load(Ordering::Acquire)
    }
}
fn device(sessions: &Sessions, state: Arc<State>) -> Device {
    Device {
        binding: ClipboardBinding {
            session_id: sessions.scope.claims.session_id.clone(),
            connection_generation: 9,
        },
        state,
    }
}

struct CleanupGatedDevice {
    inner: Device,
    complete: Arc<AtomicBool>,
    drops: Arc<AtomicUsize>,
}
impl Drop for CleanupGatedDevice {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::AcqRel);
    }
}
impl ClipboardDevice for CleanupGatedDevice {
    fn binding(&self) -> &ClipboardBinding {
        self.inner.binding()
    }
    fn consent(&self, direction: ClipboardDirection) -> Arc<dyn ClipboardConsent> {
        self.inner.consent(direction)
    }
    fn read_text(
        &mut self,
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Option<String>> {
        self.inner.read_text(check)
    }
    fn write_text(
        &mut self,
        text: &str,
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> ClipboardWriteOutcome {
        self.inner.write_text(text, check)
    }
    fn close(&mut self) -> io::Result<()> {
        self.inner.state.closed.store(true, Ordering::Release);
        if self.complete.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(io::ErrorKind::TimedOut.into())
        }
    }
    fn cleanup_complete(&self) -> bool {
        self.complete.load(Ordering::Acquire)
    }
}
async fn sessions(quic: bool, read: bool, write: bool) -> Result<Sessions> {
    let mut permissions = vec![Permission::View];
    if read {
        permissions.push(Permission::ClipboardRead);
    }
    if write {
        permissions.push(Permission::ClipboardWrite);
    }
    Sessions::with_permissions(quic, None, 9, permissions).await
}
fn payload(
    text: &str,
    permitted: Arc<AtomicBool>,
    deadline: Instant,
) -> Result<NativeClipboardPayload> {
    Ok(NativeClipboardPayload::new(
        Zeroizing::new(text.into()),
        Arc::new(Consent(permitted)),
        deadline,
    )?)
}
async fn entered(gate: &Gate) -> Result {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !gate.entered.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await?;
    Ok(())
}
async fn stop(
    sessions: &mut Sessions,
    server: &mut ClipboardServer,
    owner: &mut NativeClipboardOwner,
) -> Result {
    assert_eq!(
        owner.shutdown(Duration::from_secs(2)).await,
        NativeClipboardShutdown::Complete
    );
    // A clean clipboard retirement preserves the proved viewing lease.
    sessions
        .h
        .sender()
        .send(Channel::Video, b"view-is-still-current")
        .await?;
    assert_eq!(
        sessions.c.receive().await?.payload,
        b"view-is-still-current"
    );
    assert_eq!(
        server.shutdown(StopReason::ExplicitExit).await?,
        ClipboardShutdown::Finished
    );
    assert!(server.monitor().status().finished);
    Ok(())
}

#[tokio::test]
async fn typed_clipboard_tls_and_quic_unicode_empty_formats_and_separate_revocation() -> Result {
    for quic in [false, true] {
        let mut sessions = sessions(quic, true, true).await?;
        let state = State::new(None, None, false);
        let local = Arc::new(AtomicBool::new(true));
        let fixture = device(&sessions, state.clone());
        let binding = ClipboardBinding {
            session_id: sessions.scope.claims.session_id.clone(),
            connection_generation: 9,
        };
        let host_transport =
            ClaimedClipboardTransport::claim(&mut sessions.h, binding.clone(), BOTH)?;
        let controller_transport =
            ClaimedClipboardTransport::claim(&mut sessions.c, binding, BOTH)?;
        let mut server = ClipboardServer::start_claimed(host_transport, BOTH, fixture)?;
        let mut owner = NativeClipboardOwner::attach_claimed(controller_transport, BOTH)?;
        let handle = owner.handle();
        let completed = handle
            .send(payload(
                "中文\r\nclipboard🙂",
                local.clone(),
                Instant::now() + Duration::from_secs(2),
            )?)?
            .wait()
            .await?;
        assert!(matches!(completed.result?, NativeClipboardOutput::Written));
        assert_eq!(
            completed.write_effect,
            ClipboardWriteEffect::ClipboardWriteApplied
        );
        let completed = handle.read_remote()?.wait().await?;
        let NativeClipboardOutput::Text(mut text) = completed.result? else {
            return Err("expected actual text".into());
        };
        assert_eq!(
            text.take_text()?.as_deref().map(|text| text.as_str()),
            Some("中文\r\nclipboard🙂")
        );
        assert_eq!(text.take_text().err(), Some(NativeClipboardError::Stale));
        *state.text.lock().map_err(|_| "poisoned fixture")? = None;
        let NativeClipboardOutput::Text(mut text) = handle.read_remote()?.wait().await?.result?
        else {
            return Err("expected no-format result".into());
        };
        assert!(text.take_text()?.is_none());
        handle
            .send(payload(
                "",
                local.clone(),
                Instant::now() + Duration::from_secs(2),
            )?)?
            .wait()
            .await?
            .result?;
        let NativeClipboardOutput::Text(mut text) = handle.read_remote()?.wait().await?.result?
        else {
            return Err("expected empty-format result".into());
        };
        assert_eq!(
            text.take_text()?.as_deref().map(|text| text.as_str()),
            Some("")
        );
        state.read.store(false, Ordering::Release);
        assert!(matches!(
            handle.read_remote()?.wait().await?.result,
            Err(NativeClipboardError::Refused {
                code: ClipboardErrorCode::ClipboardDenied,
                effect: ClipboardWriteEffect::ClipboardWriteNotApplied
            })
        ));
        handle
            .send(payload(
                "write-remains-approved",
                local,
                Instant::now() + Duration::from_secs(2),
            )?)?
            .wait()
            .await?
            .result?;
        assert_eq!(state.writes.load(Ordering::Acquire), 3);
        stop(&mut sessions, &mut server, &mut owner).await?;
        assert!(state.closed.load(Ordering::Acquire));
    }
    Ok(())
}

#[tokio::test]
async fn read_revoked_while_os_call_pending_does_not_leak_old_text_or_revoke_write() -> Result {
    let mut sessions = sessions(false, true, true).await?;
    let gate = Arc::new(Gate::default());
    let state = State::new(Some(gate.clone()), None, false);
    let fixture = device(&sessions, state.clone());
    let mut server = ClipboardServer::start(&mut sessions.h, BOTH, fixture)?;
    let mut owner = NativeClipboardOwner::attach(&mut sessions.c, 9, BOTH)?;
    let ticket = owner.handle().read_remote()?;
    entered(&gate).await?;
    state.read.store(false, Ordering::Release);
    gate.release();
    assert!(matches!(
        ticket.wait().await?.result,
        Err(NativeClipboardError::Refused {
            code: ClipboardErrorCode::ClipboardDenied,
            ..
        })
    ));
    owner
        .handle()
        .send(payload(
            "write-is-independent",
            Arc::new(AtomicBool::new(true)),
            Instant::now() + Duration::from_secs(2),
        )?)?
        .wait()
        .await?
        .result?;
    assert_eq!(state.writes.load(Ordering::Acquire), 1);
    stop(&mut sessions, &mut server, &mut owner).await
}

#[tokio::test]
async fn revoked_or_expired_queued_source_is_not_applied_and_queue_budget_is_real() -> Result {
    let mut revoked_sessions = sessions(true, true, true).await?;
    let gate = Arc::new(Gate::default());
    let revoked_state = State::new(Some(gate.clone()), None, false);
    let fixture = device(&revoked_sessions, revoked_state.clone());
    let mut server = ClipboardServer::start(&mut revoked_sessions.h, BOTH, fixture)?;
    let mut owner = NativeClipboardOwner::attach(&mut revoked_sessions.c, 9, BOTH)?;
    let handle = owner.handle();
    let read = handle.read_remote()?;
    entered(&gate).await?;
    let source = Arc::new(AtomicBool::new(true));
    let write = handle.send(payload(
        "secret-local-source",
        source.clone(),
        Instant::now() + Duration::from_secs(2),
    )?)?;
    assert!(matches!(
        handle.read_remote(),
        Err(NativeClipboardError::Capacity)
    ));
    source.store(false, Ordering::Release);
    gate.release();
    drop(read.wait().await?);
    let completed = write.wait().await?;
    assert!(matches!(
        completed.result,
        Err(NativeClipboardError::Cancelled {
            effect: ClipboardWriteEffect::ClipboardWriteNotApplied
        })
    ));
    assert_eq!(revoked_state.writes.load(Ordering::Acquire), 0);
    stop(&mut revoked_sessions, &mut server, &mut owner).await?;

    // Hold a real read RPC open while an approved write waits in the owner
    // queue. Let its original deadline pass before releasing the read, so the
    // assertion cannot race a write that legitimately completed in time.
    let mut expired_sessions = sessions(true, true, true).await?;
    let gate = Arc::new(Gate::default());
    let expired_state = State::new(Some(gate.clone()), None, false);
    let fixture = device(&expired_sessions, expired_state.clone());
    let mut server = ClipboardServer::start(&mut expired_sessions.h, BOTH, fixture)?;
    let mut owner = NativeClipboardOwner::attach(&mut expired_sessions.c, 9, BOTH)?;
    let handle = owner.handle();
    let read = handle.read_remote()?;
    entered(&gate).await?;
    let write = handle.send(payload(
        "expired-source",
        Arc::new(AtomicBool::new(true)),
        Instant::now() + Duration::from_millis(100),
    )?)?;
    tokio::time::sleep(Duration::from_millis(150)).await;
    gate.release();
    drop(read.wait().await?);
    let completed = write.wait().await?;
    assert!(matches!(
        completed.result,
        Err(NativeClipboardError::Refused {
            code: ClipboardErrorCode::ClipboardExpired,
            effect: ClipboardWriteEffect::ClipboardWriteNotApplied
        })
    ));
    assert_eq!(expired_state.writes.load(Ordering::Acquire), 0);
    stop(&mut expired_sessions, &mut server, &mut owner).await
}

#[tokio::test]
async fn closing_consumes_pending_call_discards_queued_write_and_preserves_viewing() -> Result {
    let mut sessions = sessions(false, true, true).await?;
    let gate = Arc::new(Gate::default());
    let state = State::new(Some(gate.clone()), None, false);
    let fixture = device(&sessions, state.clone());
    let mut server = ClipboardServer::start(&mut sessions.h, BOTH, fixture)?;
    let mut owner = NativeClipboardOwner::attach(&mut sessions.c, 9, BOTH)?;
    let handle = owner.handle();
    let read = handle.read_remote()?;
    entered(&gate).await?;
    let queued = handle.send(payload(
        "never-dispatched",
        Arc::new(AtomicBool::new(true)),
        Instant::now() + Duration::from_secs(2),
    )?)?;
    drop(read); // Waiter Drop cannot release the in-flight operation budget.
    assert!(matches!(
        handle.read_remote(),
        Err(NativeClipboardError::Capacity)
    ));
    assert_eq!(
        owner.shutdown(Duration::from_millis(10)).await,
        NativeClipboardShutdown::Pending
    );
    assert!(!*owner.finished().borrow());
    gate.release();
    let completed = queued.wait().await?;
    assert!(matches!(
        completed.result,
        Err(NativeClipboardError::Cancelled {
            effect: ClipboardWriteEffect::ClipboardWriteNotApplied
        })
    ));
    assert_eq!(state.writes.load(Ordering::Acquire), 0);
    stop(&mut sessions, &mut server, &mut owner).await
}

#[tokio::test]
async fn unread_text_has_a_separate_budget_and_owner_drop_actively_clears_it() -> Result {
    let mut sessions = sessions(true, true, true).await?;
    let state = State::new(None, None, false);
    let fixture = device(&sessions, state.clone());
    let mut server = ClipboardServer::start(&mut sessions.h, BOTH, fixture)?;
    let mut owner = NativeClipboardOwner::attach(&mut sessions.c, 9, BOTH)?;
    let handle = owner.handle();
    let first = handle.read_remote()?.wait().await?.result?;
    let second = handle.read_remote()?.wait().await?.result?;
    assert!(matches!(
        handle.read_remote(),
        Err(NativeClipboardError::Capacity)
    ));
    let NativeClipboardOutput::Text(mut first) = first else {
        return Err("expected text".into());
    };
    assert!(first.take_text()?.is_some());
    let third = handle.read_remote()?.wait().await?.result?;
    owner.request_shutdown();
    let NativeClipboardOutput::Text(mut second) = second else {
        return Err("expected text".into());
    };
    let NativeClipboardOutput::Text(mut third) = third else {
        return Err("expected text".into());
    };
    assert_eq!(second.take_text().err(), Some(NativeClipboardError::Stale));
    assert_eq!(third.take_text().err(), Some(NativeClipboardError::Stale));
    stop(&mut sessions, &mut server, &mut owner).await
}

#[tokio::test]
async fn write_response_preserves_applied_and_unknown_effects_without_replaying() -> Result {
    for unknown in [false, true] {
        let mut sessions = sessions(false, true, true).await?;
        let gate = Arc::new(Gate::default());
        let state = State::new(None, Some(gate.clone()), unknown);
        let fixture = device(&sessions, state.clone());
        let mut server = ClipboardServer::start(&mut sessions.h, BOTH, fixture)?;
        let mut owner = NativeClipboardOwner::attach(&mut sessions.c, 9, BOTH)?;
        let ticket = owner.handle().send(payload(
            "actual-write-before-late-denial",
            Arc::new(AtomicBool::new(true)),
            Instant::now() + Duration::from_secs(2),
        )?)?;
        entered(&gate).await?;
        if !unknown {
            state.write.store(false, Ordering::Release);
        }
        gate.release();
        let completed = ticket.wait().await?;
        let effect = if unknown {
            ClipboardWriteEffect::ClipboardWriteUnknown
        } else {
            ClipboardWriteEffect::ClipboardWriteApplied
        };
        assert_eq!(completed.write_effect, effect);
        assert!(
            matches!(completed.result, Err(NativeClipboardError::Refused { effect: actual, .. }) if actual == effect)
        );
        assert_eq!(state.writes.load(Ordering::Acquire), 1);
        let NativeClipboardOutput::Text(mut text) =
            owner.handle().read_remote()?.wait().await?.result?
        else {
            return Err("expected actual current clipboard".into());
        };
        assert_eq!(
            text.take_text()?.as_deref().map(|text| text.as_str()),
            Some("actual-write-before-late-denial")
        );
        stop(&mut sessions, &mut server, &mut owner).await?;
    }
    Ok(())
}

#[tokio::test]
async fn permissions_connection_binding_and_replay_cannot_apply_another_write() -> Result {
    let mut limited = sessions(false, true, false).await?;
    assert!(
        NativeClipboardOwner::attach(
            &mut limited.c,
            9,
            ClipboardDirections {
                read: false,
                write: true
            }
        )
        .is_err()
    );
    assert!(
        NativeClipboardOwner::attach(
            &mut limited.c,
            8,
            ClipboardDirections {
                read: true,
                write: false
            }
        )
        .is_err()
    );
    let state = State::new(None, None, false);
    let fixture = device(&limited, state.clone());
    let mut read_only = ClipboardServer::start(
        &mut limited.h,
        ClipboardDirections {
            read: true,
            write: false,
        },
        fixture,
    )?;
    let mut owner = NativeClipboardOwner::attach(
        &mut limited.c,
        9,
        ClipboardDirections {
            read: true,
            write: false,
        },
    )?;
    assert!(matches!(
        owner.handle().send(payload(
            "no-write-permission",
            Arc::new(AtomicBool::new(true)),
            Instant::now() + Duration::from_secs(1)
        )?),
        Err(NativeClipboardError::Unselected)
    ));
    stop(&mut limited, &mut read_only, &mut owner).await?;

    let mut sessions = sessions(false, false, true).await?;
    let state = State::new(None, None, false);
    let fixture = device(&sessions, state.clone());
    let mut server = ClipboardServer::start(
        &mut sessions.h,
        ClipboardDirections {
            read: false,
            write: true,
        },
        fixture,
    )?;
    let mut replies = sessions.c.claim_channel(Channel::ClipboardWrite)?;
    let request = NativeClipboard {
        schema_version: SCHEMA_VERSION,
        connection_generation: 9,
        sequence: 1,
        action: Some(Action::Write("once".into())),
    }
    .encode_validated()?;
    sessions
        .c
        .sender()
        .send(Channel::ClipboardWrite, &request)
        .await?;
    assert!(matches!(
        NativeClipboard::decode_validated(&replies.receive().await?.payload)?.action,
        Some(Action::Written(true))
    ));
    sessions
        .c
        .sender()
        .send(Channel::ClipboardWrite, &request)
        .await?;
    assert!(
        tokio::time::timeout(Duration::from_secs(2), replies.receive())
            .await?
            .is_err()
    );
    assert_eq!(state.writes.load(Ordering::Acquire), 1);
    server.shutdown(StopReason::ExplicitExit).await?;
    assert!(matches!(
        sessions
            .c
            .lease_control()
            .check_channel_binding(Channel::ClipboardWrite, 9),
        Err(RemoteError::Stopped) | Err(RemoteError::Authorization(_)) | Err(RemoteError::Io(_))
    ));
    Ok(())
}

#[tokio::test]
async fn claimed_but_locally_unselected_direction_is_drained_without_os_access() -> Result {
    let mut sessions = sessions(false, true, true).await?;
    let binding = ClipboardBinding {
        session_id: sessions.scope.claims.session_id.clone(),
        connection_generation: 9,
    };
    let transport = ClaimedClipboardTransport::claim(&mut sessions.h, binding, BOTH)?;
    let state = State::new(None, None, false);
    let mut server = ClipboardServer::start_claimed(
        transport,
        ClipboardDirections {
            read: true,
            write: false,
        },
        device(&sessions, state.clone()),
    )?;
    let mut replies = sessions.c.claim_channel(Channel::ClipboardWrite)?;
    let request = NativeClipboard {
        schema_version: SCHEMA_VERSION,
        connection_generation: 9,
        sequence: 1,
        action: Some(Action::Write("must-not-reach-the-device".into())),
    }
    .encode_validated()?;
    sessions
        .c
        .sender()
        .send(Channel::ClipboardWrite, &request)
        .await?;
    let reply = NativeClipboard::decode_validated(&replies.receive().await?.payload)?;
    let Some(Action::Failure(failure)) = reply.action else {
        return Err("unselected clipboard direction was not refused".into());
    };
    assert_eq!(failure.code, ClipboardErrorCode::ClipboardDenied as i32);
    assert_eq!(
        failure.write_effect,
        ClipboardWriteEffect::ClipboardWriteNotApplied as i32
    );
    assert_eq!(state.writes.load(Ordering::Acquire), 0);
    assert_eq!(
        server.shutdown(StopReason::ExplicitExit).await?,
        ClipboardShutdown::Finished
    );
    Ok(())
}

#[tokio::test]
async fn switchable_host_denies_until_selected_then_revokes_without_stopping_view() -> Result {
    for quic in [false, true] {
        let mut sessions = sessions(quic, true, true).await?;
        let binding = ClipboardBinding {
            session_id: sessions.scope.claims.session_id.clone(),
            connection_generation: 9,
        };
        let host_transport =
            ClaimedClipboardTransport::claim(&mut sessions.h, binding.clone(), BOTH)?;
        let controller_transport =
            ClaimedClipboardTransport::claim(&mut sessions.c, binding, BOTH)?;
        let (mut server, control) =
            ClipboardServer::start_claimed_switchable(host_transport, BOTH)?;
        let mut owner = NativeClipboardOwner::attach_claimed(controller_transport, BOTH)?;
        let handle = owner.handle();
        let state = State::new(None, None, false);

        // A denied request is answered immediately while the host has no
        // platform device, so neither local OS direction can be touched.
        let denied =
            tokio::time::timeout(Duration::from_secs(1), handle.read_remote()?.wait()).await??;
        assert!(matches!(
            denied.result,
            Err(NativeClipboardError::Refused {
                code: ClipboardErrorCode::ClipboardDenied,
                effect: ClipboardWriteEffect::ClipboardWriteNotApplied,
            })
        ));
        assert_eq!(state.reads.load(Ordering::Acquire), 0);
        assert_eq!(state.writes.load(Ordering::Acquire), 0);

        // Install onto that same running owner only after an explicit local
        // direction selection; later requests can then reach the fixture OS.
        control.install(
            device(&sessions, state.clone()),
            ClipboardDirections {
                read: true,
                write: true,
            },
        )?;
        let NativeClipboardOutput::Text(mut text) = handle.read_remote()?.wait().await?.result?
        else {
            return Err("expected text after explicit host selection".into());
        };
        assert_eq!(
            text.take_text()?.as_deref().map(|text| text.as_str()),
            Some("原始中文\ntext")
        );
        assert_eq!(state.reads.load(Ordering::Acquire), 1);

        control.revoke(true, false);
        let denied = handle.read_remote()?.wait().await?;
        assert!(matches!(
            denied.result,
            Err(NativeClipboardError::Refused {
                code: ClipboardErrorCode::ClipboardDenied,
                effect: ClipboardWriteEffect::ClipboardWriteNotApplied,
            })
        ));
        assert_eq!(state.reads.load(Ordering::Acquire), 1);
        handle
            .send(payload(
                "write-direction-remains-selected",
                Arc::new(AtomicBool::new(true)),
                Instant::now() + Duration::from_secs(2),
            )?)?
            .wait()
            .await?
            .result?;
        assert_eq!(state.writes.load(Ordering::Acquire), 1);

        stop(&mut sessions, &mut server, &mut owner).await?;
        assert!(state.closed.load(Ordering::Acquire));
    }
    Ok(())
}

#[tokio::test]
async fn revoked_controller_write_consent_consumes_read_reply_and_keeps_sequence_reusable() -> Result
{
    for quic in [false, true] {
        let mut sessions = sessions(quic, true, true).await?;
        let gate = Arc::new(Gate::default());
        let state = State::new(Some(gate.clone()), None, false);
        let fixture = device(&sessions, state.clone());
        let mut server = ClipboardServer::start(&mut sessions.h, BOTH, fixture)?;
        let mut owner = NativeClipboardOwner::attach(&mut sessions.c, 9, BOTH)?;
        let handle = owner.handle();
        let consent = Arc::new(AtomicBool::new(true));

        let ticket = handle.read_remote_with_consent(Arc::new(Consent(consent.clone())))?;
        entered(&gate).await?;
        consent.store(false, Ordering::Release);
        gate.release();
        assert!(matches!(
            ticket.wait().await?.result,
            Err(NativeClipboardError::Refused {
                code: ClipboardErrorCode::ClipboardDenied,
                effect: ClipboardWriteEffect::ClipboardWriteNotApplied,
            })
        ));

        // Re-approving in this SDK fixture proves the prior exact reply was
        // consumed, its sequence advanced, and no stale response poisons the
        // next request on the same channel.
        consent.store(true, Ordering::Release);
        let NativeClipboardOutput::Text(mut text) = handle
            .read_remote_with_consent(Arc::new(Consent(consent.clone())))?
            .wait()
            .await?
            .result?
        else {
            return Err("expected the next read sequence to succeed".into());
        };
        assert_eq!(
            text.take_text()?.as_deref().map(|text| text.as_str()),
            Some("原始中文\ntext")
        );
        assert_eq!(state.reads.load(Ordering::Acquire), 2);
        stop(&mut sessions, &mut server, &mut owner).await?;
        assert!(state.closed.load(Ordering::Acquire));
    }
    Ok(())
}

#[tokio::test]
async fn switchable_owner_keeps_platform_device_until_cleanup_is_proven() -> Result {
    let mut sessions = sessions(true, true, true).await?;
    let binding = ClipboardBinding {
        session_id: sessions.scope.claims.session_id.clone(),
        connection_generation: 9,
    };
    let transport = ClaimedClipboardTransport::claim(&mut sessions.h, binding, BOTH)?;
    let (mut server, control) = ClipboardServer::start_claimed_switchable(transport, BOTH)?;
    let complete = Arc::new(AtomicBool::new(false));
    let drops = Arc::new(AtomicUsize::new(0));
    let state = State::new(None, None, false);
    control.install(
        CleanupGatedDevice {
            inner: device(&sessions, state.clone()),
            complete: complete.clone(),
            drops: drops.clone(),
        },
        BOTH,
    )?;

    assert!(control.close_device().is_err());
    assert!(control.cleanup_pending());
    assert_eq!(drops.load(Ordering::Acquire), 0);

    complete.store(true, Ordering::Release);
    control.close_device()?;
    assert!(!control.cleanup_pending());
    assert_eq!(drops.load(Ordering::Acquire), 1);
    assert_eq!(
        server.shutdown(StopReason::ExplicitExit).await?,
        ClipboardShutdown::Finished
    );
    Ok(())
}

#[tokio::test]
async fn retired_switchable_owner_rejects_late_adapter_install() -> Result {
    let mut sessions = sessions(true, true, true).await?;
    let binding = ClipboardBinding {
        session_id: sessions.scope.claims.session_id.clone(),
        connection_generation: 9,
    };
    let transport = ClaimedClipboardTransport::claim(&mut sessions.h, binding, BOTH)?;
    let (mut server, control) = ClipboardServer::start_claimed_switchable(transport, BOTH)?;
    let state = State::new(None, None, false);

    control.revoke_all();
    assert!(
        control
            .install(device(&sessions, state.clone()), BOTH)
            .is_err()
    );
    assert!(state.closed.load(Ordering::Acquire));
    assert_eq!(state.reads.load(Ordering::Acquire), 0);
    assert_eq!(state.writes.load(Ordering::Acquire), 0);
    assert!(!control.cleanup_pending());
    assert_eq!(
        server.shutdown(StopReason::ExplicitExit).await?,
        ClipboardShutdown::Finished
    );
    Ok(())
}
