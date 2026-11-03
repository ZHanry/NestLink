#![allow(clippy::unwrap_used)]
mod support;
use nestlink_app_core::*;
use nestlink_auth::{Secret, random_id};
use nestlink_protocol::{network::SpaceRole, spaces::*};
use nestlink_sdk::DeviceIdentity;
use std::time::Duration;
use support::*;
#[path = "spaces/native_path.rs"]
mod native_path;

fn scoped(handle: &CoreHandle, action: SpaceAction) -> Action {
    Action::Space {
        context: handle.snapshot().space_context.clone(),
        action,
    }
}

fn selected(handle: &CoreHandle) -> SpaceDetailsPage {
    handle
        .snapshot()
        .selected_space
        .data
        .as_ref()
        .unwrap()
        .as_ref()
        .clone()
}

async fn create(handle: &CoreHandle, name: &str) -> Result<String> {
    let completion = success(handle.submit(Action::Space {
        context: random_id(),
        action: SpaceAction::Create { name: name.into() },
    })?)
    .await?;
    let PublicOutput::Created { id } = completion.result.output else {
        return Err("created space missing".into());
    };
    assert_eq!(selected(handle).space.space_id, id);
    Ok(id)
}

async fn select(handle: &CoreHandle, space_id: &str) -> Result {
    success(handle.submit(Action::Space {
        context: random_id(),
        action: SpaceAction::Read {
            space_id: space_id.into(),
            cursor: SpacePageCursor::default(),
        },
    })?)
    .await?;
    Ok(())
}

fn invite(handle: &CoreHandle, target: Option<String>, role: SpaceRole) -> Action {
    let details = selected(handle);
    scoped(
        handle,
        SpaceAction::Invite {
            space_id: details.space.space_id,
            request: SpaceInvitationRequest {
                expected_revision: details.space.revision,
                role,
                target_account_id: target,
                expires_at_unix_ms: details.space.observed_at_unix_ms + 3_600_000,
            },
        },
    )
}

async fn enroll(handle: &CoreHandle) -> Result {
    success(handle.submit(Action::EnrollLocalDevice {
        name: "space actor device".into(),
        platform: "linux-x11".into(),
        capabilities: vec![
            "controller".into(),
            "host".into(),
            "vp8".into(),
            "opus".into(),
        ],
        path_mode: "direct_only".into(),
    })?)
    .await?;
    Ok(())
}

async fn join(handle: &CoreHandle, installation_id: &str) -> Result {
    let details = selected(handle);
    success(handle.submit(scoped(
        handle,
        SpaceAction::JoinDevice {
            space_id: details.space.space_id,
            request: SpaceDeviceJoin {
                expected_revision: details.space.revision,
                expected_membership_epoch: 0,
                installation_id: installation_id.into(),
            },
        },
    ))?)
    .await?;
    Ok(())
}

#[tokio::test]
async fn invitation_is_one_use_redacted_and_server_scoped_to_the_target_account() -> Result {
    let server = Server::start(None).await?;
    let owner_identity = DeviceIdentity::generate();
    let owner_device = owner_identity.device_id.clone();
    let mut owner_core = AppCore::with_identity(Limits::default(), owner_identity)?;
    let owner = connect(&owner_core, &server).await?;
    enroll(&owner).await?;
    let account = success(owner.submit(Action::CreateAccount {
        username: "space-guest".into(),
        password: password(),
    })?)
    .await?;
    let PublicOutput::Created { id: account_id } = account.result.output else {
        return Err("account missing".into());
    };
    let space_id = create(&owner, "delegated real HTTP space").await?;
    join(&owner, &owner_device).await?;
    let mut issued =
        success(owner.submit(invite(&owner, Some(account_id.clone()), SpaceRole::Guest))?).await?;
    let material = issued.take_sensitive().ok_or("invitation secret missing")?;
    assert_eq!(format!("{material:?}"), "SensitiveMaterial([redacted])");
    let SensitiveMaterial::SpaceInvitation {
        space_id: issued_space,
        invitation_id,
        token,
    } = material;
    assert_eq!(issued_space, space_id);
    assert!(issued.take_sensitive().is_none());
    assert!(!serde_json::to_string(owner.snapshot().as_ref())?.contains(token.expose()));
    assert!(!serde_json::to_string(&issued.result)?.contains(token.expose()));
    let wrong_account = done(owner.submit(Action::Space {
        context: random_id(),
        action: SpaceAction::Accept {
            space_id: space_id.clone(),
            invitation_id: invitation_id.clone(),
            token: Secret::from_text(token.expose().to_owned()),
        },
    })?)
    .await?;
    assert_eq!(wrong_account.result.status, OperationStatus::Failed);
    assert_eq!(wrong_account.result.failure.unwrap().status, Some(403));

    let guest_identity = DeviceIdentity::generate();
    let guest_device = guest_identity.device_id.clone();
    let mut guest_core = AppCore::with_identity(Limits::default(), guest_identity)?;
    let guest = guest_core.handle();
    success(guest.switch_server(server.config.clone())?).await?;
    success(guest.submit(Action::SignIn {
        username: "space-guest".into(),
        password: password(),
        factor: None,
    })?)
    .await?;
    enroll(&guest).await?;
    let replay = Secret::from_text(token.expose().to_owned());
    success(guest.submit(Action::Space {
        context: random_id(),
        action: SpaceAction::Accept {
            space_id: space_id.clone(),
            invitation_id: invitation_id.clone(),
            token,
        },
    })?)
    .await?;
    assert_eq!(selected(&guest).space.role, SpaceRole::Guest);
    join(&guest, &guest_device).await?;
    let details = selected(&guest);
    assert_eq!(details.members.len(), 1);
    assert_eq!(details.members[0].account_id, account_id);
    assert_eq!(details.devices.len(), 1);
    assert_eq!(details.devices[0].installation_id, guest_device);
    assert!(
        !details
            .devices
            .iter()
            .any(|device| device.installation_id == owner_device)
    );
    assert!(details.invitations.is_empty());

    let replayed = done(guest.submit(Action::Space {
        context: random_id(),
        action: SpaceAction::Accept {
            space_id: space_id.clone(),
            invitation_id,
            token: replay,
        },
    })?)
    .await?;
    assert_eq!(replayed.result.status, OperationStatus::Failed);
    assert_eq!(replayed.result.remote_effect, RemoteEffect::None);
    assert!(guest.snapshot().selected_space.data.is_none());
    select(&guest, &space_id).await?;
    let rejected = done(guest.submit(scoped(
        &guest,
        SpaceAction::Archive {
            space_id: space_id.clone(),
            request: SpaceRevisionRequest {
                expected_revision: selected(&guest).space.revision,
            },
        },
    ))?)
    .await?;
    assert_eq!(rejected.result.status, OperationStatus::Failed);
    assert_eq!(rejected.result.failure.unwrap().status, Some(403));
    assert!(guest.snapshot().selected_space.data.is_none());
    select(&owner, &space_id).await?;
    assert!(!selected(&owner).space.archived);
    assert_eq!(selected(&owner).members.len(), 2);
    assert_eq!(
        owner_core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    assert_eq!(
        guest_core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    Ok(())
}

#[tokio::test]
async fn device_revision_conflict_clears_stale_details_and_requires_a_fresh_read() -> Result {
    let server = Server::start(None).await?;
    let identity = DeviceIdentity::generate();
    let device = identity.device_id.clone();
    let mut core = AppCore::with_identity(Limits::default(), identity)?;
    let handle = connect(&core, &server).await?;
    enroll(&handle).await?;
    let space_id = create(&handle, "revision checked devices").await?;
    let old_revision = selected(&handle).space.revision;
    join(&handle, &device).await?;
    let membership_epoch = selected(&handle).devices[0].membership_epoch;
    let stale = done(handle.submit(scoped(
        &handle,
        SpaceAction::RemoveDevice {
            space_id: space_id.clone(),
            installation_id: device.clone(),
            request: SpaceDeviceRemoval {
                expected_revision: old_revision,
                expected_membership_epoch: membership_epoch,
            },
        },
    ))?)
    .await?;
    assert_eq!(stale.result.status, OperationStatus::Failed);
    assert_eq!(stale.result.remote_effect, RemoteEffect::None);
    assert_eq!(stale.result.failure.unwrap().status, Some(409));
    assert!(handle.snapshot().selected_space.data.is_none());
    select(&handle, &space_id).await?;
    let current = selected(&handle);
    assert!(current.devices[0].active);
    success(handle.submit(scoped(
        &handle,
        SpaceAction::RemoveDevice {
            space_id,
            installation_id: device,
            request: SpaceDeviceRemoval {
                expected_revision: current.space.revision,
                expected_membership_epoch: membership_epoch,
            },
        },
    ))?)
    .await?;
    assert!(!selected(&handle).devices[0].active);
    assert!(selected(&handle).devices[0].membership_epoch > membership_epoch);
    assert_eq!(
        core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    Ok(())
}

#[tokio::test]
async fn committed_invitation_reply_cannot_repopulate_a_new_same_login_space_selection() -> Result {
    let gate = Gate::suffix("/invitations", "POST");
    let server = Server::start(Some(gate.clone())).await?;
    let mut core = AppCore::start(Limits::default())?;
    let handle = connect(&core, &server).await?;
    let first = create(&handle, "old selection").await?;
    let second = create(&handle, "new selection").await?;
    select(&handle, &first).await?;
    gate.arm();
    let pending = handle.submit(invite(&handle, None, SpaceRole::Member))?;
    gate.entered().await?;
    // A second local caller can reuse a context string. The actor's own
    // monotonic selection fence must still discard the old response.
    let context = handle.snapshot().space_context.clone();
    let next = handle.submit(Action::Space {
        context: context.clone(),
        action: SpaceAction::Read {
            space_id: second.clone(),
            cursor: SpacePageCursor::default(),
        },
    })?;
    wait_view(&handle, |view| {
        view.space_context == context && view.selected_space.data.is_none()
    })
    .await?;
    assert!(handle.snapshot().selected_space.data.is_none());
    gate.unblock();
    let mut old = done(pending).await?;
    assert_eq!(old.result.status, OperationStatus::Superseded);
    assert_eq!(old.result.remote_effect, RemoteEffect::Committed);
    assert!(old.take_sensitive().is_none());
    success(next).await?;
    assert_eq!(selected(&handle).space.space_id, second);
    assert!(selected(&handle).invitations.is_empty());
    select(&handle, &first).await?;
    assert_eq!(selected(&handle).invitations.len(), 1);
    assert_eq!(
        core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    Ok(())
}

#[tokio::test]
async fn unread_invitation_slots_are_cleared_by_selection_and_logout() -> Result {
    let server = Server::start(None).await?;
    let mut core = AppCore::start(Limits::default())?;
    let handle = connect(&core, &server).await?;
    let space_id = create(&handle, "unread secret fences").await?;
    let mut before_selection =
        success(handle.submit(invite(&handle, None, SpaceRole::Member))?).await?;
    select(&handle, &space_id).await?;
    assert!(before_selection.take_sensitive().is_none());
    let mut before_logout =
        success(handle.submit(invite(&handle, None, SpaceRole::Member))?).await?;
    success(handle.logout()?).await?;
    assert!(before_logout.take_sensitive().is_none());
    let snapshot = handle.snapshot();
    assert!(snapshot.spaces.data.is_none());
    assert!(snapshot.selected_space.data.is_none());
    assert!(snapshot.space_audit.data.is_none());
    assert!(snapshot.space_services.data.is_none());
    assert!(snapshot.space_context.is_empty());
    assert_eq!(
        core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    Ok(())
}

#[tokio::test]
async fn invitation_projection_pages_remain_bounded_inside_the_original_ipc_budget() -> Result {
    let server = Server::start(None).await?;
    let mut core = AppCore::start(Limits::default())?;
    let handle = connect(&core, &server).await?;
    let space_id = create(&handle, "bounded invitations").await?;
    for index in 0..=SPACE_PAGE_SIZE {
        // Each real actor mutation also reads the resulting space projection.
        // Pace fixture creation within the unchanged 30/minute server budget;
        // a 429 is not retried and every original operation must still succeed.
        if index > 0 && index % 8 == 0 {
            tokio::time::sleep(Duration::from_millis(60_100)).await;
        }
        success(handle.submit(invite(&handle, None, SpaceRole::Member))?).await?;
    }
    let first = selected(&handle);
    assert_eq!(first.invitations.len(), SPACE_PAGE_SIZE);
    let cursor = first
        .next_invitation
        .ok_or("next invitation page missing")?;
    success(handle.submit(Action::Space {
        context: random_id(),
        action: SpaceAction::Read {
            space_id,
            cursor: SpacePageCursor {
                after_invitation: Some(cursor),
                ..Default::default()
            },
        },
    })?)
    .await?;
    let last = selected(&handle);
    assert_eq!(last.invitations.len(), 1);
    assert!(last.next_invitation.is_none());
    assert!(
        first
            .invitations
            .iter()
            .all(|first| first.invitation_id != last.invitations[0].invitation_id)
    );
    assert!(serde_json::to_vec(handle.snapshot().as_ref())?.len() < 1024 * 1024);
    assert_eq!(
        core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    Ok(())
}
