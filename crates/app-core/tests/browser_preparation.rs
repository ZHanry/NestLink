//! Actual HTTP server and automatic inbox; capture remains inert until proof.
mod support;
use nestlink_app_core::*;
use nestlink_protocol::{
    Path, Permission,
    api::{ApprovalChoice, RemoteRequest, RemoteView},
    native_displays::DisplayDescriptor,
};
use nestlink_sdk::{DeploymentTrust, DeviceIdentity, NetworkMonitor, Sdk};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use support::*;
use tokio::sync::watch;

struct Capture(Arc<AtomicUsize>);
impl BrowserHostCaptureProvider for Capture {
    fn prepare_request<'a>(
        &'a self,
        _binding: &'a BrowserHostBinding,
        _permissions: &'a [i32],
        _cancel: watch::Receiver<bool>,
    ) -> Pin<
        Box<
            dyn Future<Output = std::result::Result<PreparedBrowserCapture, BrowserHostError>>
                + Send
                + 'a,
        >,
    > {
        let starts = self.0.clone();
        Box::pin(async move {
            Ok(PreparedBrowserCapture::new(
                vec![DisplayDescriptor {
                    source: 1,
                    left: 0,
                    top: 0,
                    width: 320,
                    height: 180,
                    label: "Synthetic fixture".into(),
                }],
                move |_, _, _| {
                    starts.fetch_add(1, Ordering::SeqCst);
                    Err(nestlink_sdk::webrtc_host::WebRtcHostError::Closed)
                },
            ))
        })
    }
    fn prepare<'a>(
        &'a self,
        _id: &'a str,
        _permit: &'a nestlink_identity::VerifiedPermit,
        _cancel: watch::Receiver<bool>,
    ) -> Pin<
        Box<
            dyn Future<Output = std::result::Result<PreparedBrowserCapture, BrowserHostError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async { Err(BrowserHostError::Capture) })
    }
}

async fn setup(
    server: &Server,
) -> Result<(AppCore, CoreHandle, Sdk, RemoteView, Arc<AtomicUsize>)> {
    let identity = DeviceIdentity::generate();
    let host_id = identity.device_id.clone();
    let starts = Arc::new(AtomicUsize::new(0));
    let mut config = NativeSessionConfig::new(Arc::new(NetworkMonitor::start()?))
        .with_browser_host(BrowserHostConfig::new(Arc::new(Capture(starts.clone()))));
    // Browser preparation must also work with native auto-listening disabled
    // (the Android browser-host configuration).
    config.listen_for_native_requests = false;
    config.use_deployment_stun = false;
    let core = AppCore::with_identity_and_native_session(Limits::default(), identity, config)?;
    let host = connect(&core, server).await?;
    success(host.submit(Action::EnrollLocalDevice {
        name: "host".into(),
        platform: "windows".into(),
        capabilities: vec!["host".into(), "vp8".into()],
        path_mode: "direct_only".into(),
    })?)
    .await?;
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
    let controller = DeviceIdentity::generate();
    sdk.register_browser_endpoint(&controller, "browser".into(), "direct_only".into())
        .await?;
    let request = sdk
        .create_remote(RemoteRequest {
            id: nestlink_auth::random_id(),
            controller_device_id: controller.device_id,
            host_device_id: host_id,
            permissions: vec![Permission::View as i32],
            path_mode: "direct_only".into(),
        })
        .await?;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(
        host.snapshot().browser_host.data.is_none(),
        "pending requests must not start preparation"
    );
    success(host.submit(Action::ApproveRemote {
        request_id: request.id.clone(),
        expected_nonce: request.nonce.clone(),
        expected_policy_revision: request.policy_revision,
        choice: ApprovalChoice {
            approved: true,
            permissions: vec![Permission::View as i32],
            paths: vec![Path::Direct as i32],
        },
    })?)
    .await?;
    wait_view(&host, |view| {
        view.browser_host
            .data
            .as_ref()
            .is_some_and(|host| host.displays.approval_required)
    })
    .await?;
    Ok((core, host, sdk, request, starts))
}

async fn approve(host: &CoreHandle) -> Result {
    let view = host.snapshot();
    let offer = view.browser_host.data.as_ref().ok_or("no host")?;
    host.approve_browser_host_displays(
        offer.binding.clone().ok_or("no binding")?,
        view.generation,
        offer.displays.catalog.clone().ok_or("no catalog")?,
        vec![1],
        1,
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn automatic_host_waits_past_old_lease_then_receives_fresh_permit_and_stays_stopped() -> Result
{
    let server = Server::start(None).await?;
    let (mut core, host, sdk, request, starts) = setup(&server).await?;
    assert!(sdk.permit(&request.id).await.is_err());
    tokio::time::sleep(Duration::from_secs(16)).await;
    assert_eq!(sdk.remote(&request.id).await?.lease_sequence, 0);
    assert_eq!(starts.load(Ordering::SeqCst), 0);
    approve(&host).await?;
    tokio::time::timeout(Duration::from_secs(5), async {
        while !sdk.browser_host_readiness(&request.id).await?.ready {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<(), nestlink_sdk::SdkError>(())
    })
    .await??;
    let permit = sdk.permit(&request.id).await?;
    assert_eq!(
        permit.claims().expires_at_unix_ms - permit.claims().issued_at_unix_ms,
        nestlink_protocol::SESSION_LEASE_MS
    );
    assert_eq!(
        starts.load(Ordering::SeqCst),
        0,
        "no peer proof means no capture"
    );
    let generation = host
        .snapshot()
        .browser_host
        .data
        .as_ref()
        .ok_or("no host")?
        .connection_generation;
    success(host.submit(Action::StopBrowserHost {
        request_id: request.id.clone(),
        connection_generation: generation,
    })?)
    .await?;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        host.snapshot()
            .operations
            .iter()
            .filter(|op| op.kind == OperationKind::StartBrowserHost)
            .count(),
        1
    );
    assert_eq!(starts.load(Ordering::SeqCst), 0);
    assert_eq!(
        core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    Ok(())
}

#[tokio::test]
async fn revoked_request_cannot_become_ready_after_local_display_approval() -> Result {
    let server = Server::start(None).await?;
    let (mut core, host, sdk, request, starts) = setup(&server).await?;
    sdk.revoke_remote(&request.id).await?;
    approve(&host).await?;
    wait_view(&host, |view| {
        view.browser_host
            .data
            .as_ref()
            .is_some_and(|host| host.status == BrowserHostStatus::Failed)
    })
    .await?;
    assert!(sdk.browser_host_readiness(&request.id).await.is_err());
    assert!(sdk.permit(&request.id).await.is_err());
    assert_eq!(starts.load(Ordering::SeqCst), 0);
    assert_eq!(
        core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    Ok(())
}

#[tokio::test]
async fn stopping_during_in_flight_host_ready_write_does_not_wait_for_http_timeout() -> Result {
    let gate = Gate::suffix("/browser-host-ready", "POST");
    let server = Server::start(Some(gate.clone())).await?;
    let (mut core, host, _, request, starts) = setup(&server).await?;
    gate.arm();
    approve(&host).await?;
    gate.entered().await?;
    let generation = host
        .snapshot()
        .browser_host
        .data
        .as_ref()
        .ok_or("no host")?
        .connection_generation;
    let stop = host.submit(Action::StopBrowserHost {
        request_id: request.id,
        connection_generation: generation,
    })?;
    let result = tokio::time::timeout(Duration::from_secs(2), stop.wait()).await??;
    assert_eq!(result.result.status, OperationStatus::Succeeded);
    gate.unblock();
    assert_eq!(starts.load(Ordering::SeqCst), 0);
    assert_eq!(
        core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    Ok(())
}
