#![allow(clippy::unwrap_used)]
mod support;
use nestlink_app_core::*;
use nestlink_protocol::{
    Path, Permission,
    api::{ApprovalChoice, RemoteRequest},
};
use nestlink_sdk::{DeploymentTrust, DeviceIdentity, Sdk};
use std::{sync::atomic::Ordering, time::Duration};
use support::*;

#[tokio::test]
async fn idle_login_renews_automatically_and_logout_does_not_end_another_login() -> Result {
    let gate = Gate::new("/api/v3/auth/refresh", "POST");
    let server = Server::start(Some(gate.clone())).await?;
    let mut core = AppCore::start(Limits::default())?;
    let handle = connect(&core, &server).await?;
    let first_session = handle
        .snapshot()
        .principal
        .as_ref()
        .unwrap()
        .session_id
        .clone();
    let mut other = Sdk::connect_origin(&server.config.origin, true).await?;
    other.login("admin".into(), password(), None).await?;
    assert_ne!(first_session, other.principal().unwrap().session_id);
    gate.arm();
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(245)).await;
    tokio::time::resume();
    gate.entered().await?;
    let revision = handle.snapshot().revision;
    gate.unblock();
    wait_view(&handle, |view| view.revision > revision).await?;
    assert_eq!(handle.snapshot().authentication, Authentication::SignedIn);
    assert_eq!(
        handle.snapshot().principal.as_ref().unwrap().session_id,
        first_session
    );
    success(handle.logout()?).await?;
    assert!(other.me().await.is_ok());
    other.refresh().await?;
    other.logout().await?;
    assert_eq!(
        core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    Ok(())
}

#[test]
fn native_download_limits_are_checked_against_the_sdk_hard_caps() {
    for native_downloads in [
        NativeDownloadQueueLimits {
            active: 0,
            tasks: 1,
            reserved_bytes: 1,
        },
        NativeDownloadQueueLimits {
            active: 2,
            tasks: 1,
            reserved_bytes: 1,
        },
        NativeDownloadQueueLimits {
            active: 1,
            tasks: 1,
            reserved_bytes: u64::MAX,
        },
    ] {
        assert!(matches!(
            AppCore::start(Limits {
                native_downloads,
                ..Limits::default()
            }),
            Err(StartError::Limits)
        ));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn queued_cancel_rechecks_the_generation_when_the_actor_executes_it() -> Result {
    let mut core = AppCore::start(Limits::default())?;
    let handle = core.handle();
    let generation = handle.snapshot().generation;
    let operation = handle.submit(Action::Load {
        page: Page::Devices,
    })?;
    let logout = handle.logout_for_generation(generation)?;
    let cancel = handle.cancel_for_generation(generation, operation.id())?;

    assert!(matches!(
        cancel.wait_for_generation().await?,
        Err(SubmitError::StaleGeneration)
    ));
    assert_eq!(
        done(operation).await?.result.status,
        OperationStatus::Superseded
    );
    success(logout).await?;
    assert_eq!(
        core.shutdown(Duration::from_secs(2)).await,
        ShutdownState::Complete
    );
    Ok(())
}

#[tokio::test]
async fn switch_during_a_real_login_consumes_and_revokes_late_credentials() -> Result {
    let gate = Gate::new("/api/v3/auth/login", "POST");
    let first = Server::start(Some(gate.clone())).await?;
    let second = Server::start(None).await?;
    let mut core = AppCore::start(Limits::default())?;
    let handle = core.handle();
    success(handle.switch_server(first.config.clone())?).await?;
    gate.arm();
    let login = handle.submit(Action::SignIn {
        username: "admin".into(),
        password: password(),
        factor: None,
    })?;
    gate.entered().await?;
    let previous_generation = handle.snapshot().generation;
    let switching = handle.switch_server(second.config.clone())?;
    wait_view(&handle, |view| view.generation > previous_generation).await?;
    let clearing = handle.snapshot();
    assert_eq!(clearing.authentication, Authentication::VerifyingServer);
    assert!(clearing.principal.is_none());
    assert!(clearing.security.data.is_none());
    let queued = handle.submit(Action::Load {
        page: Page::Devices,
    })?;
    gate.unblock();
    let late = done(login).await?;
    assert_eq!(late.result.status, OperationStatus::Superseded);
    assert_eq!(late.result.remote_effect, RemoteEffect::Committed);
    success(switching).await?;
    assert_eq!(gate.logout_responses.load(Ordering::Acquire), 1);
    assert_eq!(
        handle.snapshot().server.as_ref().unwrap().deployment_id,
        second.config.deployment_id
    );
    assert_eq!(handle.snapshot().authentication, Authentication::SignedOut);
    assert_eq!(
        done(queued).await?.result.failure.unwrap().kind,
        FailureKind::SignInRequired
    );
    success(handle.submit(Action::SignIn {
        username: "admin".into(),
        password: password(),
        factor: None,
    })?)
    .await?;
    assert_eq!(
        core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    Ok(())
}

#[tokio::test]
async fn total_queue_budget_cancellation_and_committed_write_are_distinct() -> Result {
    let gate = Gate::new("/api/v3/accounts", "POST");
    let server = Server::start(Some(gate.clone())).await?;
    let mut core = AppCore::start(Limits {
        operations: 2,
        controls: 2,
        history: 8,
        sensitive_outputs: 1,
        native_downloads: Default::default(),
    })?;
    let handle = connect(&core, &server).await?;
    gate.arm();
    let active = handle.submit(Action::CreateAccount {
        username: "committed-before-cancel".into(),
        password: password(),
    })?;
    gate.entered().await?;
    let queued = handle.submit(Action::Load {
        page: Page::Devices,
    })?;
    assert!(matches!(
        handle.submit(Action::Load { page: Page::Policy }),
        Err(SubmitError::Capacity)
    ));
    assert!(handle.cancel(queued.id())?.wait().await?);
    let cancelled_queue = done(queued).await?;
    assert_eq!(cancelled_queue.result.status, OperationStatus::Cancelled);
    assert_eq!(cancelled_queue.result.remote_effect, RemoteEffect::None);
    assert!(handle.cancel(active.id())?.wait().await?);
    gate.unblock();
    let cancelled_write = done(active).await?;
    assert_eq!(cancelled_write.result.status, OperationStatus::Cancelled);
    assert_eq!(
        cancelled_write.result.remote_effect,
        RemoteEffect::Committed
    );
    assert_eq!(cancelled_write.result.output, PublicOutput::None);
    success(handle.submit(Action::Load {
        page: Page::Accounts,
    })?)
    .await?;
    assert!(
        handle
            .snapshot()
            .accounts
            .data
            .as_ref()
            .unwrap()
            .iter()
            .any(|v| v.name == "committed-before-cancel")
    );
    let mut previous = 0;
    for _ in 0..20 {
        let ticket = handle.submit(Action::Load {
            page: Page::Devices,
        })?;
        assert!(ticket.id().get() > previous);
        previous = ticket.id().get();
        success(ticket).await?;
    }
    assert!(handle.snapshot().operations.len() <= 8);
    assert!(handle.snapshot().events.len() <= 8);
    assert_eq!(
        core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    Ok(())
}

#[tokio::test]
async fn owner_drop_and_timed_shutdown_keep_slow_write_and_revoke_owned() -> Result {
    let gate = Gate::new("/api/v3/accounts", "POST");
    let server = Server::start(Some(gate.clone())).await?;
    let mut core = AppCore::start(Limits {
        operations: 1,
        ..Limits::default()
    })?;
    let handle = connect(&core, &server).await?;
    let mut finished = core.finished();
    gate.arm();
    let operation = handle.submit(Action::CreateAccount {
        username: "owned-after-window-drops".into(),
        password: password(),
    })?;
    gate.entered().await?;
    // An abandoned UI waiter cannot release the active-operation reservation.
    let operation_id = operation.id();
    drop(operation);
    assert!(matches!(
        handle.submit(Action::Load {
            page: Page::Devices
        }),
        Err(SubmitError::Capacity)
    ));
    assert_eq!(
        core.shutdown(Duration::from_millis(20)).await,
        ShutdownState::Pending
    );
    wait_view(&handle, |view| view.lifecycle == Lifecycle::Stopping).await?;
    assert!(!*finished.borrow());
    assert!(handle.snapshot().principal.is_none());
    drop(core);
    assert!(matches!(
        handle.submit(Action::Load {
            page: Page::Devices
        }),
        Err(SubmitError::Stopped)
    ));
    gate.unblock();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !*finished.borrow_and_update() {
            finished.changed().await?;
        }
        Ok::<(), tokio::sync::watch::error::RecvError>(())
    })
    .await??;
    assert_eq!(handle.snapshot().lifecycle, Lifecycle::Stopped);
    assert_eq!(gate.logout_responses.load(Ordering::Acquire), 1);
    assert!(
        handle
            .snapshot()
            .operations
            .iter()
            .any(|record| record.id == operation_id
                && record.status == OperationStatus::Superseded
                && record.remote_effect == RemoteEffect::Committed)
    );
    Ok(())
}

#[tokio::test]
async fn access_expiry_recovers_with_refresh_without_retiring_the_management_session() -> Result {
    let gate = Gate::new("/api/v3/auth/refresh", "POST");
    let server = Server::start(Some(gate.clone())).await?;
    let mut core = AppCore::start(Limits::default())?;
    let handle = connect(&core, &server).await?;
    let session = handle
        .snapshot()
        .principal
        .as_ref()
        .unwrap()
        .session_id
        .clone();
    gate.arm();
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(301)).await;
    tokio::time::resume();
    gate.entered().await?;
    assert_eq!(handle.snapshot().authentication, Authentication::SignedIn);
    gate.unblock();
    success(handle.submit(Action::Load {
        page: Page::Devices,
    })?)
    .await?;
    assert_eq!(
        handle.snapshot().principal.as_ref().unwrap().session_id,
        session
    );
    assert_eq!(gate.logout_responses.load(Ordering::Acquire), 0);
    assert_eq!(
        core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    Ok(())
}

#[tokio::test]
async fn unread_completed_results_are_fenced_at_logout() -> Result {
    let server = Server::start(None).await?;
    let mut core = AppCore::start(Limits::default())?;
    let handle = connect(&core, &server).await?;
    let created = handle.submit(Action::CreateAccount {
        username: "old-account-page".into(),
        password: password(),
    })?;
    wait_view(&handle, |view| {
        view.accounts.data.as_ref().is_some_and(|accounts| {
            accounts
                .iter()
                .any(|account| account.name == "old-account-page")
        })
    })
    .await?;
    success(handle.logout()?).await?;
    let old_account = done(created).await?;
    assert_eq!(old_account.result.status, OperationStatus::Superseded);
    assert_eq!(old_account.result.output, PublicOutput::None);
    assert!(handle.snapshot().accounts.data.is_none());
    assert!(
        handle
            .snapshot()
            .events
            .iter()
            .all(|event| matches!(event.result.output, PublicOutput::None))
    );
    assert_eq!(
        core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    Ok(())
}

#[tokio::test]
async fn guarded_client_actions_and_boundaries_cannot_attach_to_a_new_account() -> Result {
    let first = Server::start(None).await?;
    let second = Server::start(None).await?;
    let mut core = AppCore::start(Limits::default())?;
    let first_client = connect(&core, &first).await?;
    let second_client = core.handle();
    let generation = first_client.snapshot().generation;
    // No await between these admissions: both clients saw the same old view.
    let logout = second_client.logout_for_generation(generation)?;
    let stale_switch =
        first_client.switch_server_for_generation(generation, second.config.clone())?;
    let stale_write = first_client.submit_for_generation(
        generation,
        Action::CreateAccount {
            username: "must-never-be-created".into(),
            password: password(),
        },
    )?;
    success(logout).await?;
    assert_eq!(
        done(stale_switch).await?.result.status,
        OperationStatus::Superseded
    );
    assert_eq!(
        done(stale_write).await?.result.remote_effect,
        RemoteEffect::None
    );
    assert_eq!(
        first_client
            .snapshot()
            .server
            .as_ref()
            .unwrap()
            .deployment_id,
        first.config.deployment_id
    );
    assert!(matches!(
        first_client.submit_for_generation(
            generation,
            Action::Load {
                page: Page::Devices
            }
        ),
        Err(SubmitError::StaleGeneration)
    ));
    assert!(matches!(
        first_client.logout_for_generation(generation),
        Err(SubmitError::StaleGeneration)
    ));
    assert!(matches!(
        first_client.switch_server_for_generation(generation, second.config.clone()),
        Err(SubmitError::StaleGeneration)
    ));
    success(second_client.submit_for_generation(
        second_client.snapshot().generation,
        Action::SignIn {
            username: "admin".into(),
            password: password(),
            factor: None,
        },
    )?)
    .await?;
    success(second_client.submit_for_generation(
        second_client.snapshot().generation,
        Action::Load {
            page: Page::Accounts,
        },
    )?)
    .await?;
    assert!(
        second_client
            .snapshot()
            .accounts
            .data
            .as_ref()
            .unwrap()
            .iter()
            .all(|account| account.name != "must-never-be-created")
    );
    assert_eq!(
        core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    Ok(())
}

#[tokio::test]
async fn cancel_during_approval_read_does_not_dispatch_the_later_write() -> Result {
    let request_id = nestlink_auth::random_id();
    let gate = Gate::new(format!("/api/v3/remote/{request_id}"), "GET");
    let server = Server::start(Some(gate.clone())).await?;
    let host = DeviceIdentity::generate();
    let host_id = host.device_id.clone();
    let mut core = AppCore::with_identity(Limits::default(), host)?;
    let handle = connect(&core, &server).await?;
    success(handle.submit(Action::EnrollLocalDevice {
        name: "host".into(),
        platform: "windows".into(),
        capabilities: vec!["host".into(), "vp8".into()],
        path_mode: "direct_only".into(),
    })?)
    .await?;
    let controller = DeviceIdentity::generate();
    let mut sdk = Sdk::connect(
        &server.config.origin,
        DeploymentTrust {
            deployment_id: server.config.deployment_id.clone(),
            permit_issuer: server.config.permit_issuer,
        },
        true,
    )
    .await?;
    sdk.login("admin".into(), password(), None).await?;
    sdk.enroll(
        &controller,
        "controller".into(),
        "windows".into(),
        vec!["controller".into(), "vp8".into()],
        "direct_only".into(),
    )
    .await?;
    let request = sdk
        .create_remote(RemoteRequest {
            id: request_id.clone(),
            controller_device_id: controller.device_id.clone(),
            host_device_id: host_id,
            permissions: vec![Permission::View as i32],
            path_mode: "direct_only".into(),
        })
        .await?;
    gate.arm();
    let approval = handle.submit(Action::ApproveRemote {
        request_id: request_id.clone(),
        expected_nonce: request.nonce,
        expected_policy_revision: request.policy_revision,
        choice: ApprovalChoice {
            approved: true,
            permissions: vec![Permission::View as i32],
            paths: vec![Path::Direct as i32],
        },
    })?;
    gate.entered().await?;
    assert!(handle.cancel(approval.id())?.wait().await?);
    gate.unblock();
    let completed = done(approval).await?;
    assert_eq!(completed.result.status, OperationStatus::Cancelled);
    assert_eq!(completed.result.remote_effect, RemoteEffect::None);
    assert_eq!(sdk.remote(&request_id).await?.status, "pending");
    sdk.logout().await?;
    assert_eq!(
        core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn results_are_published_before_cross_thread_receivers_observe_completion() -> Result {
    let server = Server::start(None).await?;
    let identity = DeviceIdentity::generate();
    let mut core = AppCore::with_identity(Limits::default(), identity)?;
    let handle = connect(&core, &server).await?;
    assert_eq!(handle.snapshot().authentication, Authentication::SignedIn);
    for index in 0..8 {
        let result = success(handle.submit(Action::CreateAccount {
            username: format!("published-{index}"),
            password: password(),
        })?)
        .await?;
        let PublicOutput::Created { id } = result.result.output else {
            panic!("account result missing");
        };
        let view = handle.snapshot();
        assert_eq!(view.generation, result.result.generation);
        assert!(
            view.accounts
                .data
                .as_ref()
                .unwrap()
                .iter()
                .any(|account| account.id == id)
        );
        assert!(
            view.operations
                .iter()
                .any(|operation| operation.id == result.result.id
                    && operation.status == OperationStatus::Succeeded)
        );
    }
    success(handle.logout()?).await?;
    let view = handle.snapshot();
    assert_eq!(view.authentication, Authentication::SignedOut);
    assert!(view.principal.is_none());
    assert!(view.installation.is_some());
    assert_eq!(
        core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    Ok(())
}
