//! Real HTTP + WebSocket + inner TLS: one controller action wakes a signed-in
//! host without a second UI click or an independent relay node.
mod support;
use nestlink_app_core::*;
use nestlink_protocol::{
    Path, Permission,
    api::{ApprovalChoice, NetworkPolicy, PolicyUpdate},
};
use nestlink_sdk::{DeviceIdentity, NetworkMonitor};
use std::{sync::Arc, time::Duration};
use support::*;

fn core(identity: DeviceIdentity, listen: bool) -> Result<AppCore> {
    let monitor = Arc::new(NetworkMonitor::start()?);
    let mut config = NativeSessionConfig::new(monitor);
    // Bind only a private NIC. An additional public/VPN NIC could otherwise
    // provide a successful direct path, making this fallback assertion false.
    // No private dialing prefix is approved, so these signed LAN candidates
    // cannot be dialed and the real combined WSS route must carry the session.
    let address = if_addrs::get_if_addrs()?
        .into_iter()
        .find(|interface| {
            interface.is_oper_up()
                && matches!(interface.ip(), std::net::IpAddr::V4(ip) if ip.is_private())
        })
        .ok_or("the WSS fallback fixture requires an active private IPv4 NIC")?;
    config.bind_address = std::net::SocketAddr::new(address.ip(), 0);
    config.use_deployment_stun = false;
    config.listen_for_native_requests = listen;
    Ok(AppCore::with_identity_and_native_session(
        Limits::default(),
        identity,
        config,
    )?)
}

async fn wait_connected(handle: &CoreHandle) -> Result {
    tokio::time::timeout(Duration::from_secs(25), async {
        loop {
            if let Some(session) = &handle.snapshot().native_session.data {
                if session.status == NativeSessionStatus::Connected {
                    return Ok(());
                }
                if session.status == NativeSessionStatus::Failed {
                    return Err(format!("session failed: {:?}", session.failure).into());
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await?
}

#[tokio::test]
async fn controller_alone_starts_approved_host_over_combined_wss_and_stop_is_respected() -> Result {
    session_and_stop(false, false).await
}

#[tokio::test]
async fn manually_started_host_is_not_restarted_by_the_inbox_after_stop() -> Result {
    session_and_stop(true, false).await
}

#[tokio::test]
async fn relay_only_inbox_needs_no_direct_candidate_or_private_network_consent() -> Result {
    session_and_stop(false, true).await
}

async fn session_and_stop(manual_host: bool, relay_only: bool) -> Result {
    let path_mode = if relay_only {
        "relay_only"
    } else {
        "direct_preferred"
    };
    let server = Server::start(None).await?;
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    let host_id = host.device_id.clone();
    let mut controller_core = core(controller, false)?;
    let mut host_core = core(host, true)?;
    let controller = connect(&controller_core, &server).await?;
    let host = connect(&host_core, &server).await?;
    success(controller.submit(Action::SetPolicy {
        update: PolicyUpdate {
            expected_revision: 1,
            policy: NetworkPolicy {
                server_forwarding: "allow".into(),
                peer_path_mode: path_mode.into(),
                public_ingress: "disabled".into(),
            },
        },
    })?)
    .await?;
    for (handle, role) in [(&controller, "controller"), (&host, "host")] {
        success(handle.submit(Action::EnrollLocalDevice {
            name: role.into(),
            platform: "windows".into(),
            capabilities: vec![role.into(), "vp8".into(), "opus".into()],
            path_mode: path_mode.into(),
        })?)
        .await?;
    }
    success(controller.submit(Action::RequestRemote {
        host_device_id: host_id,
        permissions: vec![Permission::View as i32],
        path_mode: path_mode.into(),
        access: RemoteAccess::LocalApproval,
    })?)
    .await?;
    let request = controller
        .snapshot()
        .selected_request
        .data
        .as_ref()
        .ok_or("no request")?
        .clone();
    // Polling must never turn a pending request into consent.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(host.snapshot().native_session.data.is_none());
    success(host.submit(Action::ApproveRemote {
        request_id: request.id.clone(),
        expected_nonce: request.nonce.clone(),
        expected_policy_revision: request.policy_revision,
        choice: ApprovalChoice {
            approved: true,
            permissions: vec![Permission::View as i32],
            paths: if relay_only {
                vec![Path::Relay as i32]
            } else {
                vec![Path::Direct as i32, Path::Relay as i32]
            },
        },
    })?)
    .await?;
    success(controller.submit(Action::IssueRemotePermit {
        request_id: request.id.clone(),
    })?)
    .await?;
    // Also cover a manually started (or recovered) generation, which has no
    // inbox attempt marker. Its explicit stop must consume the wake-up hint.
    let host_start = if manual_host {
        Some(host.submit(Action::StartNativeSession {
            relay_node_id: None,
            request_id: request.id.clone(),
        })?)
    } else {
        None
    };
    let completion = tokio::time::timeout(
        Duration::from_secs(25),
        controller
            .submit(Action::StartNativeSession {
                relay_node_id: None,
                request_id: request.id.clone(),
            })?
            .wait(),
    )
    .await??;
    assert_eq!(
        completion.result.status,
        OperationStatus::Succeeded,
        "{:?}",
        completion.result.failure
    );
    if let Some(ticket) = host_start {
        success(ticket).await?;
    }
    wait_connected(&host).await?;
    let controller_view = controller
        .snapshot()
        .native_session
        .data
        .as_ref()
        .ok_or("no controller session")?
        .clone();
    let host_view = host
        .snapshot()
        .native_session
        .data
        .as_ref()
        .ok_or("no host session")?
        .clone();
    assert_eq!(controller_view.path, Some(Path::Relay as i32));
    assert_eq!(host_view.path, Some(Path::Relay as i32));
    assert!(host_view.host_view_authorized);
    success(host.submit(Action::StopNativeSession {
        request_id: request.id.clone(),
        connection_generation: host_view.connection_generation,
    })?)
    .await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_ne!(
        host.snapshot()
            .native_session
            .data
            .as_ref()
            .ok_or("lost stopped session")?
            .status,
        NativeSessionStatus::Connected
    );
    assert_eq!(
        host.snapshot()
            .operations
            .iter()
            .filter(|operation| operation.kind == OperationKind::StartNativeSession)
            .count(),
        1
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
