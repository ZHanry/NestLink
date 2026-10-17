#![allow(clippy::unwrap_used)]
mod support;
use nestlink_app_core::*;
use nestlink_auth::{Secret, totp};
use std::time::Duration;
use support::*;

fn decode_base32(text: &str) -> Result<Vec<u8>> {
    let mut accumulator = 0u32;
    let mut bits = 0;
    let mut decoded = Vec::new();
    for byte in text.bytes() {
        let digit = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
            .iter()
            .position(|value| *value == byte)
            .ok_or("invalid TOTP seed")?;
        accumulator = (accumulator << 5) | digit as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            decoded.push((accumulator >> bits) as u8);
        }
    }
    Ok(decoded)
}

#[tokio::test]
async fn real_totp_and_recovery_login_one_shot_outputs_password_change_and_clear() -> Result {
    let server = Server::start(None).await?;
    let mut core = AppCore::start(Limits {
        sensitive_outputs: 1,
        ..Limits::default()
    })?;
    let handle = connect(&core, &server).await?;
    // Wrong password/factor during step-up doesn't turn a valid access token
    // into an expired account. The core checks the actual /auth/me result.
    let wrong = done(handle.submit(Action::BeginTotp {
        password: Secret::from_text("wrong-but-long-password".into()),
        factor: None,
    })?)
    .await?;
    assert_eq!(wrong.result.status, OperationStatus::Failed);
    assert_eq!(wrong.result.failure.unwrap().status, Some(401));
    assert_eq!(handle.snapshot().authentication, Authentication::SignedIn);
    let mut beginning = success(handle.submit(Action::BeginTotp {
        password: password(),
        factor: None,
    })?)
    .await?;
    let capacity = done(handle.submit(Action::BeginTotp {
        password: password(),
        factor: None,
    })?)
    .await?;
    assert_eq!(capacity.result.failure.unwrap().kind, FailureKind::Capacity);
    assert_eq!(capacity.result.remote_effect, RemoteEffect::None);
    let Some(SensitiveMaterial::TotpSeed(seed)) = beginning.take_sensitive() else {
        panic!("missing TOTP seed");
    };
    assert!(beginning.take_sensitive().is_none());
    assert!(!serde_json::to_string(handle.snapshot().as_ref())?.contains(seed.expose()));
    let code = totp(&decode_base32(seed.expose())?, seconds()? / 30)?;
    let mut confirmed = success(handle.submit(Action::ConfirmTotp {
        code: Secret::from_text(code),
    })?)
    .await?;
    let Some(SensitiveMaterial::RecoveryCodes(codes)) = confirmed.take_sensitive() else {
        panic!("missing recovery codes");
    };
    assert_eq!(codes.len(), 10);
    assert!(
        handle
            .snapshot()
            .security
            .data
            .as_ref()
            .unwrap()
            .totp_enabled
    );
    let text = serde_json::to_string(handle.snapshot().as_ref())?;
    assert!(codes.iter().all(|code| !text.contains(code.expose())));
    success(handle.logout()?).await?;
    assert_eq!(handle.snapshot().logout_confirmed, Some(true));
    let without_factor = done(handle.submit(Action::SignIn {
        username: "admin".into(),
        password: password(),
        factor: None,
    })?)
    .await?;
    assert_eq!(without_factor.result.status, OperationStatus::Failed);
    assert_eq!(handle.snapshot().authentication, Authentication::SignedOut);
    // The server intentionally returns a generic rejection for password/MFA.
    success(handle.submit(Action::SignIn {
        username: "admin".into(),
        password: password(),
        factor: Some(Secret::from_text(codes[0].expose().into())),
    })?)
    .await?;
    success(handle.logout()?).await?;
    let replay = done(handle.submit(Action::SignIn {
        username: "admin".into(),
        password: password(),
        factor: Some(Secret::from_text(codes[0].expose().into())),
    })?)
    .await?;
    assert_eq!(replay.result.status, OperationStatus::Failed);
    success(handle.submit(Action::SignIn {
        username: "admin".into(),
        password: password(),
        factor: Some(Secret::from_text(codes[1].expose().into())),
    })?)
    .await?;
    let changed = success(handle.submit(Action::ChangePassword {
        current_password: password(),
        new_password: Secret::from_text("new-app-core-password".into()),
        factor: Some(Secret::from_text(codes[2].expose().into())),
    })?)
    .await?;
    assert_eq!(changed.result.remote_effect, RemoteEffect::Committed);
    assert_eq!(handle.snapshot().authentication, Authentication::Expired);
    assert!(handle.snapshot().principal.is_none());
    assert!(handle.snapshot().security.data.is_none());
    success(handle.submit(Action::SignIn {
        username: "admin".into(),
        password: Secret::from_text("new-app-core-password".into()),
        factor: Some(Secret::from_text(codes[3].expose().into())),
    })?)
    .await?;
    let mut reset = success(handle.submit(Action::ResetRecovery {
        password: Secret::from_text("new-app-core-password".into()),
        factor: Secret::from_text(codes[4].expose().into()),
    })?)
    .await?;
    // A reply can remain unconsumed across logout. Its slot must be zeroized
    // immediately, not when the UI finally drops the completion or ticket.
    success(handle.logout()?).await?;
    assert!(reset.take_sensitive().is_none());
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
