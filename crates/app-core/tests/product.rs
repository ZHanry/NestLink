#![allow(clippy::unwrap_used)]
mod support;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_app_core::*;
use nestlink_auth::Secret;
use nestlink_identity::nodes::NodeIdentity;
use nestlink_protocol::{NodeRole, Path, Permission, api::*};
use nestlink_sdk::DeviceIdentity;
use std::time::Duration;
use support::*;

#[tokio::test]
async fn real_sdk_accounts_devices_policy_nodes_audit_and_role_rejection() -> Result {
    let server = Server::start(None).await?;
    let identity = DeviceIdentity::generate();
    let device_id = identity.device_id.clone();
    let fingerprint = identity.identity.fingerprint();
    let mut core = AppCore::with_identity(Limits::default(), identity)?;
    let handle = connect(&core, &server).await?;
    let initial = handle.snapshot();
    assert_eq!(initial.authentication, Authentication::SignedIn);
    assert_eq!(initial.installation.as_ref().unwrap().device_id, device_id);
    assert_eq!(
        initial.installation.as_ref().unwrap().public_key_sha256,
        fingerprint
    );
    assert!(initial.server.as_ref().unwrap().verified_health.is_some());
    success(handle.submit(Action::EnrollLocalDevice {
        name: "真实控制端".into(),
        platform: "windows".into(),
        capabilities: vec!["controller".into(), "vp8".into()],
        path_mode: "direct_only".into(),
    })?)
    .await?;
    assert!(
        handle
            .snapshot()
            .devices
            .data
            .as_ref()
            .unwrap()
            .iter()
            .any(|v| v.device.id == device_id)
    );
    let created = success(handle.submit(Action::CreateAccount {
        username: "member".into(),
        password: password(),
    })?)
    .await?;
    let PublicOutput::Created { id: member_id } = created.result.output else {
        panic!("missing account id");
    };
    assert!(
        handle
            .snapshot()
            .accounts
            .data
            .as_ref()
            .unwrap()
            .iter()
            .any(|v| v.id == member_id)
    );
    success(handle.submit(Action::Load { page: Page::Policy })?).await?;
    let revision = handle.snapshot().policy.data.as_ref().unwrap().revision;
    success(handle.submit(Action::SetPolicy {
        update: PolicyUpdate {
            expected_revision: revision,
            policy: NetworkPolicy {
                server_forwarding: "deny".into(),
                peer_path_mode: "direct_only".into(),
                public_ingress: "disabled".into(),
            },
        },
    })?)
    .await?;
    let policy_revision = handle.snapshot().policy.data.as_ref().unwrap().revision;
    assert_eq!(policy_revision, revision + 1);
    success(handle.submit(Action::SetPathLimit {
        scope: "device".into(),
        resource_id: device_id.clone(),
        update: PathLimitUpdate {
            expected_revision: policy_revision,
            path_mode: "direct_only".into(),
        },
    })?)
    .await?;
    assert!(
        handle
            .snapshot()
            .path_limits
            .data
            .as_ref()
            .unwrap()
            .iter()
            .any(|v| v.resource_id == device_id)
    );
    success(handle.submit(Action::Load {
        page: Page::RelayQuota,
    })?)
    .await?;
    let quota = *handle
        .snapshot()
        .relay_quota
        .data
        .as_ref()
        .unwrap()
        .as_ref();
    success(handle.submit(Action::SetRelayQuota {
        update: RelayQuotaUpdate {
            expected_revision: quota.revision,
            limits: quota.limits,
        },
    })?)
    .await?;
    let node_id = nestlink_auth::random_id();
    let node = NodeIdentity::generate();
    success(handle.submit(Action::RegisterNode {
        node: NodeRegistration {
            id: node_id.clone(),
            name: "真实节点".into(),
            public_key: URL_SAFE_NO_PAD.encode(node.public_key()),
            roles: vec![NodeRole::NodeRelay as i32],
            max_connections: 16,
            bytes_per_second: 1024,
        },
    })?)
    .await?;
    assert!(
        handle
            .snapshot()
            .nodes
            .data
            .as_ref()
            .unwrap()
            .iter()
            .any(|v| v.node.id == node_id)
    );
    success(handle.submit(Action::LoadNodeUsage {
        node_id: node_id.clone(),
        after_generation: 0,
        limit: 10,
    })?)
    .await?;
    assert!(
        handle
            .snapshot()
            .node_usage
            .data
            .as_ref()
            .unwrap()
            .entries
            .is_empty()
    );
    success(handle.submit(Action::RevokeNode {
        node_id: node_id.clone(),
    })?)
    .await?;
    assert!(
        handle
            .snapshot()
            .nodes
            .data
            .as_ref()
            .unwrap()
            .iter()
            .find(|v| v.node.id == node_id)
            .unwrap()
            .revoked
    );
    success(handle.submit(Action::Load {
        page: Page::AuditRetention,
    })?)
    .await?;
    let retention_revision = handle
        .snapshot()
        .audit_retention
        .data
        .as_ref()
        .unwrap()
        .revision;
    success(handle.submit(Action::SetAuditRetention {
        update: AuditRetentionUpdate {
            expected_revision: retention_revision,
            retention_seconds: 3600,
        },
    })?)
    .await?;
    success(handle.submit(Action::LoadAudit {
        after_sequence: 0,
        limit: 100,
    })?)
    .await?;
    assert!(
        handle
            .snapshot()
            .audit
            .data
            .as_ref()
            .unwrap()
            .entries
            .iter()
            .any(|entry| entry.event == "node_registered")
    );
    let encoded = serde_json::to_vec(handle.snapshot().as_ref())?;
    let decoded: Snapshot = serde_json::from_slice(&encoded)?;
    assert_eq!(decoded.generation, handle.snapshot().generation);
    let snapshot_text = String::from_utf8(encoded)?;
    assert!(!snapshot_text.contains(PASSWORD));
    assert!(!snapshot_text.contains("refresh_token"));
    assert!(!snapshot_text.contains("access_token"));
    // A normal account's 403 doesn't destroy its valid management session.
    success(handle.logout()?).await?;
    assert_eq!(
        handle.snapshot().installation.as_ref().unwrap().device_id,
        device_id
    );
    success(handle.submit(Action::SignIn {
        username: "member".into(),
        password: password(),
        factor: None,
    })?)
    .await?;
    let rejected = done(handle.submit(Action::Load {
        page: Page::Accounts,
    })?)
    .await?;
    assert_eq!(rejected.result.status, OperationStatus::Failed);
    assert_eq!(rejected.result.failure.as_ref().unwrap().status, Some(403));
    assert_eq!(handle.snapshot().authentication, Authentication::SignedIn);
    assert!(handle.snapshot().accounts.data.is_none());
    success(handle.submit(Action::Load {
        page: Page::Devices,
    })?)
    .await?;
    assert!(handle.snapshot().devices.data.as_ref().unwrap().is_empty());
    assert_eq!(
        core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    Ok(())
}

#[tokio::test]
async fn actual_local_approval_trust_password_access_and_revocation() -> Result {
    let server = Server::start(None).await?;
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    let host_id = host.device_id.clone();
    let mut control_core = AppCore::with_identity(Limits::default(), controller)?;
    let mut host_core = AppCore::with_identity(Limits::default(), host)?;
    let controller_handle = connect(&control_core, &server).await?;
    let host_handle = connect(&host_core, &server).await?;
    for (handle, capability) in [(&controller_handle, "controller"), (&host_handle, "host")] {
        success(handle.submit(Action::EnrollLocalDevice {
            name: capability.into(),
            platform: "linux-x11".into(),
            capabilities: vec![capability.into(), "vp8".into()],
            path_mode: "direct_only".into(),
        })?)
        .await?;
    }
    success(controller_handle.submit(Action::RequestRemote {
        host_device_id: host_id.clone(),
        permissions: vec![Permission::View as i32, Permission::Input as i32],
        path_mode: "direct_only".into(),
        access: RemoteAccess::LocalApproval,
    })?)
    .await?;
    let request = controller_handle
        .snapshot()
        .selected_request
        .data
        .as_ref()
        .unwrap()
        .clone();
    success(host_handle.submit(Action::Load {
        page: Page::Requests,
    })?)
    .await?;
    assert!(
        host_handle
            .snapshot()
            .requests
            .data
            .as_ref()
            .unwrap()
            .iter()
            .any(|v| v.id == request.id)
    );
    let stale = done(host_handle.submit(Action::ApproveRemote {
        request_id: request.id.clone(),
        expected_nonce: "stale".into(),
        expected_policy_revision: request.policy_revision,
        choice: ApprovalChoice {
            approved: true,
            permissions: vec![Permission::View as i32],
            paths: vec![Path::Direct as i32],
        },
    })?)
    .await?;
    assert_eq!(stale.result.status, OperationStatus::Failed);
    assert_eq!(stale.result.remote_effect, RemoteEffect::None);
    success(host_handle.submit(Action::ApproveRemote {
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
    let approved = host_handle
        .snapshot()
        .selected_request
        .data
        .as_ref()
        .unwrap()
        .clone();
    assert_eq!(approved.status, "approved");
    assert_eq!(approved.permissions, vec![Permission::View as i32]);
    success(controller_handle.submit(Action::IssueRemotePermit {
        request_id: request.id.clone(),
    })?)
    .await?;
    assert_eq!(
        controller_handle
            .snapshot()
            .selected_request
            .data
            .as_ref()
            .unwrap()
            .lease_sequence,
        1
    );
    success(host_handle.submit(Action::TrustRemote {
        request_id: request.id.clone(),
        choice: TrustChoice {
            expected_revision: 0,
            expires_at_unix_ms: (seconds()? + 600) * 1000,
        },
    })?)
    .await?;
    let trust_revision = host_handle
        .snapshot()
        .trusted_devices
        .data
        .as_ref()
        .unwrap()
        .devices[0]
        .revision;
    success(controller_handle.submit(Action::RequestRemote {
        host_device_id: host_id.clone(),
        permissions: vec![Permission::View as i32],
        path_mode: "direct_only".into(),
        access: RemoteAccess::TrustedDevice,
    })?)
    .await?;
    assert_eq!(
        controller_handle
            .snapshot()
            .selected_request
            .data
            .as_ref()
            .unwrap()
            .status,
        "approved"
    );
    success(host_handle.submit(Action::RevokeDeviceTrust {
        host_device_id: host_id.clone(),
        controller_device_id: request.controller_device_id.clone(),
        expected_revision: trust_revision,
    })?)
    .await?;
    assert!(
        !host_handle
            .snapshot()
            .trusted_devices
            .data
            .as_ref()
            .unwrap()
            .devices[0]
            .active
    );
    success(host_handle.submit(Action::ConfigureRemotePassword {
        settings: RemotePasswordSettings {
            expected_revision: 0,
            permissions: vec![Permission::View as i32],
            paths: vec![Path::Direct as i32],
            expires_at_unix_ms: (seconds()? + 600) * 1000,
        },
        password: Secret::from_text("remote-password-test-value".into()),
    })?)
    .await?;
    let password_revision = host_handle
        .snapshot()
        .remote_password
        .data
        .as_ref()
        .unwrap()
        .settings
        .revision;
    success(controller_handle.submit(Action::RequestRemote {
        host_device_id: host_id.clone(),
        permissions: vec![Permission::View as i32],
        path_mode: "direct_only".into(),
        access: RemoteAccess::LocalApproval,
    })?)
    .await?;
    let password_request = controller_handle
        .snapshot()
        .selected_request
        .data
        .as_ref()
        .unwrap()
        .id
        .clone();
    success(controller_handle.submit(Action::LoadRemotePasswordOffer {
        request_id: password_request.clone(),
    })?)
    .await?;
    let offer_snapshot = controller_handle.snapshot();
    let offer = offer_snapshot.remote_password_offer.data.as_ref().unwrap();
    assert_eq!(offer.request_id, password_request);
    assert!(offer.settings.active);
    assert_eq!(offer.settings.revision, password_revision);
    success(controller_handle.submit(Action::AuthorizeRemotePassword {
        request_id: password_request.clone(),
        expected_revision: offer.settings.revision,
        password: Secret::from_text("remote-password-test-value".into()),
    })?)
    .await?;
    assert_eq!(
        controller_handle
            .snapshot()
            .selected_request
            .data
            .as_ref()
            .unwrap()
            .status,
        "approved"
    );
    success(controller_handle.submit(Action::RevokeRemote {
        request_id: password_request,
    })?)
    .await?;
    assert_eq!(
        controller_handle
            .snapshot()
            .selected_request
            .data
            .as_ref()
            .unwrap()
            .status,
        "revoked"
    );
    success(host_handle.submit(Action::RevokeRemotePassword {
        expected_revision: password_revision,
    })?)
    .await?;
    assert!(
        !host_handle
            .snapshot()
            .remote_password
            .data
            .as_ref()
            .unwrap()
            .settings
            .active
    );
    success(host_handle.submit(Action::RevokeDevice { device_id: host_id })?).await?;
    assert!(
        host_handle
            .snapshot()
            .devices
            .data
            .as_ref()
            .unwrap()
            .iter()
            .any(|v| v.revoked)
    );
    assert_eq!(
        control_core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    assert_eq!(
        host_core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    Ok(())
}
