//! Authorization-only synthetic signed evidence, never a hardware qualification.
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{VaultKey, hash_password, random_id};
use nestlink_identity::{InstallationIdentity, PermitSigner, digest, verify_permit};
use nestlink_protocol::api::{
    ApprovalChoice, DeviceDescriptor, DeviceRegistration, MediaAnnouncementSubmission,
    MediaApprovalChoice, MediaApprovalSubmission, MediaRemoteRequest, RemoteRequest, RemoteView,
};
use nestlink_protocol::internal_software_media_candidate::InternalSoftwareMediaCandidate;
use nestlink_protocol::media_authority::{
    FrozenMediaScope, MediaAnnouncement, MediaDirection, ProbeIdentity,
};
use nestlink_protocol::media_format::{FrameRate, VideoFormat};
use nestlink_protocol::{DeviceAction, DeviceActionClaims, Permission, SCHEMA_VERSION};
use nestlink_server::{AppState, router};
use nestlink_storage::{Store, accounts::Principal};
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};
use tower::ServiceExt;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn enroll(
    store: &mut Store,
    principal: &Principal,
    identity: &InstallationIdentity,
    now: u64,
) -> Result<String> {
    let challenge = store.enrollment_challenge(principal, now)?;
    let id = random_id();
    let mut body = DeviceRegistration {
        challenge_id: challenge.id,
        device: DeviceDescriptor {
            id: id.clone(),
            name: "candidate authorization test".into(),
            platform: "windows".into(),
            public_key: URL_SAFE_NO_PAD.encode(identity.public_key()),
            capabilities: vec!["controller".into(), "host".into(), "vp8".into()],
            path_mode: "direct_only".into(),
        },
        signature: String::new(),
    };
    body.signature = URL_SAFE_NO_PAD
        .encode(identity.sign_action(&store.registration_transcript(principal, &body, now)?)?);
    store.register_device(principal, body, now)?;
    Ok(id)
}
fn announce(
    store: &mut Store,
    principal: &Principal,
    identity: &InstallationIdentity,
    id: &str,
    direction: MediaDirection,
    formats: Vec<Vec<u8>>,
    now: u64,
) -> Result {
    let challenge = store.enrollment_challenge(principal, now)?;
    let mut body = MediaAnnouncementSubmission {
        challenge_id: challenge.id,
        announcement: MediaAnnouncement {
            version: 2,
            device_id: id.into(),
            direction,
            revision: 1,
            expires_at_unix_ms: (now + 240) * 1000,
            probe: ProbeIdentity {
                generation: 1,
                resource_id: random_id(),
                backend: "cpu-software".into(),
                adapter_luid: None,
                driver_version: None,
            },
            formats,
        },
        signature: String::new(),
    };
    body.signature = URL_SAFE_NO_PAD.encode(
        identity.sign_action(&store.media_announcement_transcript(principal, &body, now)?)?,
    );
    store.replace_media_announcement(principal, body, now)?;
    Ok(())
}
async fn call(
    app: &Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Value,
) -> Result<(StatusCode, Value)> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("Content-Type", "application/json");
    if let Some(token) = token {
        request = request.header("Authorization", format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(serde_json::to_vec(&body)?))?)
        .await?;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 262_144).await?;
    Ok((
        status,
        if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)?
        },
    ))
}
#[tokio::test]
async fn internal_candidate_http_requires_scope_auth_first_approval_and_both_renewal_proofs()
-> Result {
    candidate_http(false).await
}
#[tokio::test]
async fn internal_candidate_http_freezes_all_explicit_lower_formats_through_approval_and_renewal()
-> Result {
    candidate_http(true).await
}
async fn candidate_http(adaptive: bool) -> Result {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let deployment = random_id();
    let mut store = Store::in_memory(&deployment)?;
    let password = "internal-candidate-authorization-only";
    store.bootstrap_admin("admin", password)?;
    let vault = VaultKey::from_bytes([31; 32]);
    let grant = store.login(
        "admin",
        password,
        None,
        now,
        &vault,
        &hash_password(password)?,
    )?;
    let principal = grant.principal;
    let token = grant.access_token.expose().to_owned();
    let epoch = store.security_epoch()?;
    let controller = InstallationIdentity::generate();
    let host = InstallationIdentity::generate();
    let cid = enroll(&mut store, &principal, &controller, now)?;
    let hid = enroll(&mut store, &principal, &host, now)?;
    let format = VideoFormat::legacy_h264(31, 320, 240, FrameRate::new(30, 1)?, 2000)?;
    let additional_formats = if adaptive {
        vec![
            VideoFormat::legacy_h264(31, 320, 240, FrameRate::new(22, 1)?, 1500)?.encode()?,
            VideoFormat::legacy_h264(31, 160, 120, FrameRate::new(15, 1)?, 1000)?.encode()?,
        ]
    } else {
        Vec::new()
    };
    let policy = InternalSoftwareMediaCandidate {
        deployment_id: deployment.clone(),
        account_id: principal.account_id.clone(),
        controller_device_id: cid.clone(),
        host_device_id: hid.clone(),
        format: format.encode()?,
        format_sha256: format.digest()?,
        additional_formats,
    };
    let exact_formats = policy.formats()?;
    announce(
        &mut store,
        &principal,
        &controller,
        &cid,
        MediaDirection::Decode,
        exact_formats.clone(),
        now,
    )?;
    announce(
        &mut store,
        &principal,
        &host,
        &hid,
        MediaDirection::Encode,
        exact_formats.clone(),
        now,
    )?;
    let request = MediaRemoteRequest {
        media_format_version: 2,
        request: RemoteRequest {
            id: random_id(),
            controller_device_id: cid.clone(),
            host_device_id: hid.clone(),
            permissions: vec![Permission::View as i32],
            path_mode: "direct_only".into(),
        },
    };
    assert!(
        store
            .create_media_remote(&principal, request.clone(), now)
            .is_err()
    );
    let store = store.with_internal_software_media_candidate(policy)?;
    let issuer = PermitSigner::generate();
    let public_key = issuer.public_key();
    let app = router(AppState::new(
        store,
        vault,
        issuer,
        "https://console.example.test".into(),
        true,
    )?);
    let (status, _) = call(
        &app,
        "POST",
        "/api/v3/remote/media",
        None,
        serde_json::to_value(&request)?,
    )
    .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let mut other = request.clone();
    other.request.host_device_id = random_id();
    other.request.id = random_id();
    let (status, _) = call(
        &app,
        "POST",
        "/api/v3/remote/media",
        Some(&token),
        serde_json::to_value(&other)?,
    )
    .await?;
    assert!(!status.is_success());
    let (status, value) = call(
        &app,
        "POST",
        "/api/v3/remote/media",
        Some(&token),
        serde_json::to_value(&request)?,
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED);
    let view: RemoteView = serde_json::from_value(value)?;
    assert_eq!(view.status, "pending");
    let permit_path = format!("/api/v3/remote/{}/permit", view.id);
    let (status, _) = call(&app, "POST", &permit_path, Some(&token), Value::Null).await?;
    assert!(!status.is_success());
    let (status, scope) = call(
        &app,
        "GET",
        &format!("/api/v3/remote/{}/media", view.id),
        Some(&token),
        Value::Null,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    let scope: FrozenMediaScope = serde_json::from_value(scope)?;
    assert_eq!(scope.formats, exact_formats);
    let choice = MediaApprovalChoice {
        choice: ApprovalChoice {
            approved: true,
            permissions: vec![1],
            paths: vec![1],
        },
        media_format_sha256: scope.sha256.clone(),
    };
    let proof = DeviceActionClaims {
        schema_version: SCHEMA_VERSION,
        action: DeviceAction::Approve as i32,
        deployment_id: deployment.clone(),
        security_epoch: epoch,
        account_id: principal.account_id.clone(),
        device_id: hid.clone(),
        resource_id: view.id.clone(),
        challenge: URL_SAFE_NO_PAD.decode(&view.nonce)?,
        payload_sha256: digest(&serde_json::to_vec(&(
            "nestlink/media-approval/v2",
            &choice,
            &scope,
        ))?)
        .to_vec(),
        expires_at_unix_ms: view.expires_at_unix_ms,
    };
    let approval = MediaApprovalSubmission {
        choice,
        signature: URL_SAFE_NO_PAD.encode(host.sign_action(&proof)?),
    };
    let (status, _) = call(
        &app,
        "POST",
        &format!("/api/v3/remote/{}/media/approval", view.id),
        Some(&token),
        serde_json::to_value(&approval)?,
    )
    .await?;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, initial) = call(&app, "POST", &permit_path, Some(&token), Value::Null).await?;
    assert_eq!(status, StatusCode::OK);
    let initial = verify_permit(
        &URL_SAFE_NO_PAD.decode(initial["permit"].as_str().ok_or("permit absent")?)?,
        &public_key,
    )?;
    assert_eq!(initial.claims().media_formats, scope.formats);
    assert!(
        initial
            .claims()
            .required_capabilities
            .iter()
            .any(|value| value == nestlink_protocol::media::H264_CAPABILITY)
    );
    let sequence = initial.claims().lease_sequence + 1;
    let renewal_nonce = URL_SAFE_NO_PAD.decode(&view.nonce)?;
    let transcript = |id: &str| DeviceActionClaims {
        schema_version: SCHEMA_VERSION,
        action: DeviceAction::Renew as i32,
        deployment_id: deployment.clone(),
        security_epoch: epoch,
        account_id: principal.account_id.clone(),
        device_id: id.into(),
        resource_id: view.id.clone(),
        challenge: renewal_nonce.clone(),
        payload_sha256: digest(&sequence.to_be_bytes()).to_vec(),
        expires_at_unix_ms: initial.claims().expires_at_unix_ms,
    };
    let mut renewal = json!({"lease_sequence":sequence, "controller_signature":URL_SAFE_NO_PAD.encode(controller.sign_action(&transcript(&cid))?), "host_signature":""});
    let renew_path = format!("/api/v3/remote/{}/renew", view.id);
    let (status, _) = call(&app, "POST", &renew_path, Some(&token), renewal.clone()).await?;
    assert!(!status.is_success());
    renewal["host_signature"] =
        Value::String(URL_SAFE_NO_PAD.encode(host.sign_action(&transcript(&hid))?));
    let (status, next) = call(&app, "POST", &renew_path, Some(&token), renewal).await?;
    assert_eq!(status, StatusCode::OK);
    let next = verify_permit(
        &URL_SAFE_NO_PAD.decode(next["permit"].as_str().ok_or("next absent")?)?,
        &public_key,
    )?;
    assert_eq!(next.claims().lease_sequence, sequence);
    assert_eq!(next.claims().media_formats, initial.claims().media_formats);
    assert_eq!(
        next.claims().media_format_sha256,
        initial.claims().media_format_sha256
    );
    Ok(())
}
