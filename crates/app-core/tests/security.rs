#![allow(clippy::unwrap_used)]
mod support;
use nestlink_app_core::*;
use nestlink_auth::Secret;
use std::time::Duration;
use support::*;

#[tokio::test]
async fn password_change_reauthenticates_and_requires_a_new_login() -> Result {
    let server = Server::start(None).await?;
    let mut core = AppCore::start(Limits::default())?;
    let handle = connect(&core, &server).await?;
    let wrong = done(handle.submit(Action::ChangePassword {
        current_password: Secret::from_text("wrong-but-long-password".into()),
        new_password: Secret::from_text("new-password-only-login".into()),
        factor: None,
    })?)
    .await?;
    assert_eq!(wrong.result.status, OperationStatus::Failed);
    assert_eq!(handle.snapshot().authentication, Authentication::SignedIn);
    success(handle.submit(Action::ChangePassword {
        current_password: password(),
        new_password: Secret::from_text("new-password-only-login".into()),
        factor: None,
    })?)
    .await?;
    assert_ne!(handle.snapshot().authentication, Authentication::SignedIn);
    let old = done(handle.submit(Action::SignIn {
        username: "admin".into(),
        password: password(),
        factor: None,
    })?)
    .await?;
    assert_eq!(old.result.status, OperationStatus::Failed);
    success(handle.submit(Action::SignIn {
        username: "admin".into(),
        password: Secret::from_text("new-password-only-login".into()),
        factor: None,
    })?)
    .await?;
    assert_eq!(handle.snapshot().authentication, Authentication::SignedIn);
    assert!(
        !serde_json::to_string(handle.snapshot().as_ref())?.contains("new-password-only-login")
    );
    for action in ["begin_totp", "confirm_totp", "reset_recovery"] {
        assert!(serde_json::from_value::<Action>(serde_json::json!({"action": action})).is_err());
    }
    assert_eq!(
        core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    Ok(())
}

#[tokio::test]
async fn origin_only_connection_discovers_metadata_and_checks_signed_identity() -> Result {
    let server = Server::start(None).await?;
    let mut core = AppCore::start(Limits::default())?;
    let handle = core.handle();
    success(handle.switch_server(ApprovedServer::from_origin(
        server.config.origin.clone(),
        true,
    ))?)
    .await?;
    let snapshot = handle.snapshot();
    let resolved = snapshot.server.as_ref().unwrap();
    assert_eq!(resolved.deployment_id, server.config.deployment_id);
    assert_eq!(resolved.approved_issuer, server.config.permit_issuer);
    success(handle.submit(Action::SignIn {
        username: "admin".into(),
        password: password(),
        factor: None,
    })?)
    .await?;
    assert_eq!(handle.snapshot().authentication, Authentication::SignedIn);
    let client = reqwest::Client::new();
    for endpoint in ["totp", "totp/confirm", "recovery"] {
        let response = client
            .post(format!("{}/api/v3/auth/{endpoint}", server.config.origin))
            .header("Origin", &server.config.origin)
            .json(&serde_json::json!({}))
            .send()
            .await?;
        assert_eq!(response.status().as_u16(), 404);
    }
    assert_eq!(
        core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    Ok(())
}

#[tokio::test]
async fn late_discovery_cannot_replace_metadata_of_the_new_origin() -> Result {
    let first_gate = Gate::new("/api/v3/health/proof", "POST");
    let second_gate = Gate::new("/api/v3/health", "GET");
    let first = Server::start(Some(first_gate.clone())).await?;
    let second = Server::start(Some(second_gate.clone())).await?;
    let mut core = AppCore::start(Limits::default())?;
    let handle = core.handle();
    first_gate.arm();
    second_gate.arm();
    let old = handle.switch_server(ApprovedServer::from_origin(
        first.config.origin.clone(),
        true,
    ))?;
    first_gate.entered().await?;
    let generation = handle.snapshot().generation;
    let new = handle.switch_server(ApprovedServer::from_origin(
        second.config.origin.clone(),
        true,
    ))?;
    wait_view(&handle, |view| view.generation > generation).await?;
    first_gate.unblock();
    assert_eq!(done(old).await?.result.status, OperationStatus::Superseded);
    second_gate.entered().await?;
    let snapshot = handle.snapshot();
    let pending = snapshot.server.as_ref().unwrap();
    assert_eq!(pending.origin, second.config.origin);
    assert!(pending.deployment_id.is_empty());
    assert_eq!(pending.approved_issuer, [0; 32]);
    assert!(pending.verified_health.is_none());
    second_gate.unblock();
    success(new).await?;
    assert_eq!(
        handle.snapshot().server.as_ref().unwrap().deployment_id,
        second.config.deployment_id
    );
    assert_eq!(
        core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    Ok(())
}

#[tokio::test]
async fn trust_failure_and_wire_actions_do_not_create_authority_or_leak_history() -> Result {
    let server = Server::start(None).await?;
    let mut core = AppCore::start(Limits::default())?;
    let handle = core.handle();
    let mut incorrect = server.config.clone();
    incorrect.permit_issuer = [19; 32];
    let rejected = done(handle.switch_server(incorrect)?).await?;
    assert_eq!(rejected.result.failure.unwrap().kind, FailureKind::Trust);
    assert_eq!(
        handle.snapshot().authentication,
        Authentication::Disconnected
    );
    assert!(
        handle
            .snapshot()
            .server
            .as_ref()
            .unwrap()
            .verified_health
            .is_none()
    );
    let action: Action = serde_json::from_str(
        r#"{"action":"sign_in","username":"admin","password":"app-core-real-http-password","factor":null}"#,
    )?;
    let denied = done(handle.submit(action)?).await?;
    assert_eq!(
        denied.result.failure.unwrap().kind,
        FailureKind::SignInRequired
    );
    assert!(
        serde_json::from_str::<Action>(r#"{"action":"refresh_session","executable":"inject.exe"}"#)
            .is_err()
    );
    assert!(
        serde_json::from_str::<Action>(r#"{"action":"load","page":"devices","unknown":true}"#)
            .is_err()
    );
    success(handle.switch_server(server.config.clone())?).await?;
    success(handle.submit(Action::SignIn {
        username: "admin".into(),
        password: password(),
        factor: None,
    })?)
    .await?;
    let identity_required = done(handle.submit(Action::EnrollLocalDevice {
        name: "unregistered".into(),
        platform: "windows".into(),
        capabilities: vec!["vp8".into()],
        path_mode: "direct_only".into(),
    })?)
    .await?;
    assert_eq!(
        identity_required.result.failure.unwrap().kind,
        FailureKind::LocalIdentityRequired
    );
    let view = serde_json::to_string(handle.snapshot().as_ref())?;
    assert!(!view.contains(PASSWORD));
    assert!(!view.contains("private_key"));
    assert_eq!(
        core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    Ok(())
}
