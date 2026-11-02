//! Real AppCore/HTTP entry rejects invalid GPU requests before a direction probe.
mod support;
use nestlink_app_core::*;
use nestlink_media_codec::VideoConfig;
use nestlink_protocol::{
    Permission,
    api::ApprovalChoice,
    media_authority::FrozenMediaScope,
    media_format::{FormatSet, FrameRate, VideoFormat},
};
use nestlink_sdk::{DeviceIdentity, NetworkMonitor};
use std::{sync::Arc, time::Duration};
use support::*;

#[tokio::test]
async fn explicit_gpu_request_rejects_trusted_access_and_missing_view_before_publication() -> Result
{
    gpu_request_boundaries(false).await
}
#[tokio::test]
async fn explicit_main10_request_rejects_trusted_access_and_missing_view_before_publication()
-> Result {
    gpu_request_boundaries(true).await
}
async fn gpu_request_boundaries(main10: bool) -> Result {
    let server = Server::start(None).await?;
    let config = NativeSessionConfig::new(Arc::new(NetworkMonitor::start()?));
    let target = VideoConfig {
        width: 640,
        height: 480,
        fps: 30,
        bitrate_kbps: 4000,
    };
    let config = if main10 {
        config.with_gpu_hevc_main10_target(target)?
    } else {
        config.with_gpu_hevc_main8_target(target)?
    };
    let mut core = AppCore::with_identity_and_native_session(
        Limits::default(),
        DeviceIdentity::generate(),
        config,
    )?;
    let handle = connect(&core, &server).await?;
    for (access, permissions, expected) in [
        (
            RemoteAccess::TrustedDevice,
            vec![Permission::View as i32],
            FailureKind::NativeSessionUnavailable,
        ),
        (
            RemoteAccess::LocalApproval,
            vec![Permission::Input as i32],
            FailureKind::Trust,
        ),
    ] {
        let completion = done(handle.submit(Action::RequestRemote {
            host_device_id: nestlink_auth::random_id(),
            permissions,
            path_mode: "direct_only".into(),
            access,
        })?)
        .await?;
        assert_eq!(completion.result.status, OperationStatus::Failed);
        assert_eq!(completion.result.remote_effect, RemoteEffect::None);
        assert_eq!(
            completion.result.failure.ok_or("failure absent")?.kind,
            expected
        );
        assert!(handle.snapshot().selected_request.data.is_none());
    }
    assert_eq!(
        core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    Ok(())
}

#[tokio::test]
async fn legacy_pending_request_cannot_be_reinterpreted_as_reviewed_gpu_media() -> Result {
    legacy_pending_boundary(false).await
}
#[tokio::test]
async fn legacy_pending_request_cannot_be_reinterpreted_as_reviewed_main10_media() -> Result {
    legacy_pending_boundary(true).await
}
async fn legacy_pending_boundary(main10: bool) -> Result {
    let server = Server::start(None).await?;
    let host_identity = DeviceIdentity::generate();
    let host_id = host_identity.device_id.clone();
    let config = NativeSessionConfig::new(Arc::new(NetworkMonitor::start()?));
    let target = VideoConfig {
        width: 640,
        height: 480,
        fps: 30,
        bitrate_kbps: 4000,
    };
    let config = if main10 {
        config.with_gpu_hevc_main10_target(target)?
    } else {
        config.with_gpu_hevc_main8_target(target)?
    };
    let mut host_core =
        AppCore::with_identity_and_native_session(Limits::default(), host_identity, config)?;
    let mut controller_core =
        AppCore::with_identity(Limits::default(), DeviceIdentity::generate())?;
    let host = connect(&host_core, &server).await?;
    let controller = connect(&controller_core, &server).await?;
    for (handle, role) in [(&host, "host"), (&controller, "controller")] {
        success(handle.submit(Action::EnrollLocalDevice {
            name: role.into(),
            platform: "windows".into(),
            capabilities: vec![role.into(), "vp8".into()],
            path_mode: "direct_only".into(),
        })?)
        .await?;
    }
    success(controller.submit(Action::RequestRemote {
        host_device_id: host_id,
        permissions: vec![Permission::View as i32],
        path_mode: "direct_only".into(),
        access: RemoteAccess::LocalApproval,
    })?)
    .await?;
    let request = controller
        .snapshot()
        .selected_request
        .data
        .clone()
        .ok_or("request absent")?;
    let mut ptl = [0; 12];
    ptl[0] = if main10 { 2 } else { 1 };
    ptl[11] = 120;
    // Only a syntax fixture for a rejection. No GPU announcement or receipt is fabricated.
    let constructor = if main10 {
        VideoFormat::hevc_main10_observed
    } else {
        VideoFormat::hevc_main8_observed
    };
    let format = constructor(ptl, 640, 480, FrameRate::new(30, 1)?, 4000)?;
    let set = FormatSet::new(vec![format])?;
    let rejected = done(host.submit(Action::ApproveMediaRemote {
        request_id: request.id.clone(),
        expected_nonce: request.nonce.clone(),
        expected_policy_revision: request.policy_revision,
        choice: ApprovalChoice {
            approved: true,
            permissions: request.permissions.clone(),
            paths: request.paths.clone(),
        },
        reviewed_scope: FrozenMediaScope {
            version: if main10 { 4 } else { 3 },
            controller_revision: 1,
            host_revision: 1,
            formats: vec![format.encode()?],
            sha256: set.digest().to_vec(),
        },
    })?)
    .await?;
    assert_eq!(rejected.result.status, OperationStatus::Failed);
    assert_eq!(rejected.result.remote_effect, RemoteEffect::None);
    assert_eq!(
        rejected.result.failure.ok_or("failure absent")?.kind,
        FailureKind::Trust
    );
    success(host.submit(Action::InspectRemote {
        request_id: request.id.clone(),
    })?)
    .await?;
    assert_eq!(
        host.snapshot()
            .selected_request
            .data
            .as_ref()
            .ok_or("pending request absent")?
            .status,
        "pending"
    );
    assert!(
        host.snapshot()
            .selected_media_scope
            .data
            .as_ref()
            .is_some_and(|scope| scope.is_none())
    );
    assert_eq!(
        host_core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    assert_eq!(
        controller_core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    Ok(())
}
