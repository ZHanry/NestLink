mod support;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_app_core::*;
use nestlink_auth::random_id;
use nestlink_identity::nodes::NodeIdentity;
use nestlink_protocol::{NodeRole, api::*};
use nestlink_sdk::DeviceIdentity;
use std::time::Duration;
use support::*;

async fn prepare(server: &Server) -> Result<(AppCore, CoreHandle, ServiceCreate)> {
    let identity = DeviceIdentity::generate();
    let host = identity.device_id.clone();
    let core = AppCore::with_identity(Limits::default(), identity)?;
    let handle = connect(&core, server).await?;
    success(handle.submit(Action::EnrollLocalDevice {
        name: "locally enrolled service host".into(),
        platform: "linux-x11".into(),
        capabilities: vec!["host".into(), "vp8".into()],
        path_mode: "direct_only".into(),
    })?)
    .await?;
    let edge = random_id();
    let node_identity = NodeIdentity::generate();
    success(handle.submit(Action::RegisterNode {
        node: NodeRegistration {
            id: edge.clone(),
            name: "service test edge".into(),
            public_key: URL_SAFE_NO_PAD.encode(node_identity.public_key()),
            roles: vec![NodeRole::NodeEdge as i32],
            max_connections: 8,
            bytes_per_second: 1_048_576,
        },
    })?)
    .await?;
    let create = ServiceCreate {
        id: random_id(),
        definition: ServiceDefinition {
            name: "Core configuration".into(),
            host_device_id: host,
            edge_node_id: edge,
            requested_ingress: ServiceIngress::Tcp { port: 29100 },
            allowed_sources: vec![],
            limits: ServiceLimits {
                maximum_connections: 8,
                bytes_per_second: 1_048_576,
                maximum_bytes: 1_073_741_824,
                idle_timeout_seconds: 60,
            },
        },
    };
    Ok((core, handle, create))
}

fn local_host_request(handle: &CoreHandle, runtime_id: &str) -> Result<LocalServiceHostRequest> {
    let snapshot = handle.snapshot();
    let service = snapshot
        .selected_service
        .data
        .as_ref()
        .ok_or("missing selected service")?;
    Ok(LocalServiceHostRequest {
        runtime_id: runtime_id.to_owned(),
        expected_generation: snapshot.generation,
        expected_snapshot_revision: snapshot.revision,
        service_id: service.id.clone(),
        service_revision: service.revision,
        definition_sha256: service.definition_sha256.clone(),
        protocol: "tcp".into(),
        address: "127.0.0.1:28080".into(),
        backend_tls: None,
    })
}

#[tokio::test]
async fn host_preview_is_local_one_use_and_cannot_outlive_its_reviewed_revision() -> Result {
    let server = Server::start(None).await?;
    let (mut core, handle, create) = prepare(&server).await?;
    success(handle.submit(Action::CreateService { create })?).await?;
    let runtime = random_id();
    let mut stale = local_host_request(&handle, &runtime)?;
    stale.expected_snapshot_revision = stale.expected_snapshot_revision.saturating_sub(1);
    assert!(matches!(
        handle.preview_local_service_host(stale).await,
        Err(SubmitError::StaleGeneration)
    ));

    let preview = handle
        .preview_local_service_host(local_host_request(&handle, &runtime)?)
        .await?;
    assert_eq!(preview.address, "127.0.0.1:28080");
    assert_eq!(preview.service.revision, 1);
    assert_eq!(preview.service.approval, ServiceApprovalState::Pending);
    assert!(handle.snapshot().local_service_host.is_none());

    let generation = handle.snapshot().generation;
    let other_runtime = done(handle.start_local_service_host_for_generation(
        random_id(),
        generation,
        preview.nonce.clone(),
    )?)
    .await?;
    assert_eq!(other_runtime.result.status, OperationStatus::Superseded);
    let replay = done(handle.start_local_service_host_for_generation(
        runtime.clone(),
        generation,
        preview.nonce,
    )?)
    .await?;
    assert_eq!(replay.result.status, OperationStatus::Failed);
    assert!(handle.snapshot().local_service_host.is_none());

    let preview = handle
        .preview_local_service_host(local_host_request(&handle, &runtime)?)
        .await?;
    let mut definition = preview.service.definition.clone();
    definition.name = "Changed after local review".into();
    success(handle.submit(Action::UpdateService {
        service_id: preview.service.id,
        update: ServiceUpdate {
            expected_revision: 1,
            definition,
        },
    })?)
    .await?;
    let changed =
        done(handle.start_local_service_host_for_generation(runtime, generation, preview.nonce)?)
            .await?;
    assert_eq!(changed.result.status, OperationStatus::Superseded);
    let snapshot = handle.snapshot();
    let current = snapshot
        .selected_service
        .data
        .as_ref()
        .ok_or("missing updated service")?;
    assert_eq!(current.revision, 2);
    assert_eq!(current.approval, ServiceApprovalState::Pending);
    assert!(snapshot.local_service_host.is_none());
    assert_eq!(
        core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    Ok(())
}

#[tokio::test]
async fn host_approval_reply_after_logout_is_consumed_without_starting_a_forwarder() -> Result {
    let service_id = random_id();
    // The server owns its real registry and gates only the response
    // after approval commits, so no SDK or authorization reply is fabricated.
    let gate = Gate::new(format!("/api/v3/services/{service_id}/approval"), "POST");
    let server = Server::start(Some(gate.clone())).await?;
    let (mut core, handle, mut create) = prepare(&server).await?;
    create.id = service_id;
    success(handle.submit(Action::CreateService { create })?).await?;
    // A fresh deployment denies public ingress. Enable it through the real
    // administrator API before gating a successfully committed approval.
    success(handle.submit(Action::Load { page: Page::Policy })?).await?;
    let policy_revision = handle
        .snapshot()
        .policy
        .data
        .as_ref()
        .ok_or("missing policy")?
        .revision;
    success(handle.submit(Action::SetPolicy {
        update: PolicyUpdate {
            expected_revision: policy_revision,
            policy: NetworkPolicy {
                server_forwarding: "allow".into(),
                peer_path_mode: "direct_only".into(),
                public_ingress: "enabled".into(),
            },
        },
    })?)
    .await?;
    let runtime = random_id();
    let preview = handle
        .preview_local_service_host(local_host_request(&handle, &runtime)?)
        .await?;
    let generation = handle.snapshot().generation;
    gate.arm();
    let starting =
        handle.start_local_service_host_for_generation(runtime, generation, preview.nonce)?;
    gate.entered().await.map_err(|error| {
        format!(
            "approval response did not reach the gate: {error}; operations: {:?}",
            handle.snapshot().operations
        )
    })?;
    let logout = handle.logout()?;
    wait_view(&handle, |view| view.generation > generation)
        .await
        .map_err(|error| format!("logout did not advance generation: {error}"))?;
    gate.unblock();
    let late = done(starting)
        .await
        .map_err(|error| format!("late approval was not consumed: {error}"))?;
    assert_eq!(late.result.status, OperationStatus::Superseded);
    assert_eq!(late.result.remote_effect, RemoteEffect::Committed);
    success(logout).await?;
    let snapshot = handle.snapshot();
    assert_eq!(snapshot.authentication, Authentication::SignedOut);
    assert!(snapshot.selected_service.data.is_none());
    assert!(snapshot.local_service_host.as_ref().is_none_or(|host| {
        host.status == LocalServiceHostStatus::Stopped && !host.cleanup_failed
    }));
    assert_eq!(
        core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    Ok(())
}

#[tokio::test]
async fn core_uses_real_registry_revisions_and_clears_service_views_at_logout() -> Result {
    let server = Server::start(None).await?;
    let (mut core, handle, create) = prepare(&server).await?;
    success(handle.submit(Action::Load {
        page: Page::Services,
    })?)
    .await?;
    assert!(
        handle
            .snapshot()
            .services
            .data
            .as_ref()
            .ok_or("missing service page")?
            .services
            .is_empty()
    );
    let id = create.id.clone();
    let mut definition = create.definition.clone();
    success(handle.submit(Action::CreateService { create })?).await?;
    let created = handle.snapshot();
    let record = created
        .selected_service
        .data
        .as_ref()
        .ok_or("missing created service")?;
    assert_eq!(record.id, id);
    assert_eq!(record.revision, 1);
    assert_eq!(record.approval, ServiceApprovalState::Pending);
    assert_eq!(record.publication, ServicePublicationStatus::NotPublished);
    definition.name = "Updated Core configuration".into();
    success(handle.submit(Action::UpdateService {
        service_id: id.clone(),
        update: ServiceUpdate {
            expected_revision: 1,
            definition: definition.clone(),
        },
    })?)
    .await?;
    let rejected = done(handle.submit(Action::UpdateService {
        service_id: id.clone(),
        update: ServiceUpdate {
            expected_revision: 1,
            definition,
        },
    })?)
    .await?;
    assert_eq!(rejected.result.status, OperationStatus::Failed);
    assert_eq!(
        rejected.result.failure.ok_or("missing conflict")?.status,
        Some(409)
    );
    assert_eq!(handle.snapshot().authentication, Authentication::SignedIn);
    success(handle.submit(Action::LoadServicesPage {
        after_id: None,
        limit: 1,
    })?)
    .await?;
    let first = handle
        .snapshot()
        .services
        .data
        .clone()
        .ok_or("missing first service page")?;
    assert_eq!(first.services.len(), 1);
    success(handle.submit(Action::LoadServicesPage {
        after_id: first.next_id.clone(),
        limit: 1,
    })?)
    .await?;
    assert!(
        handle
            .snapshot()
            .services
            .data
            .as_ref()
            .ok_or("missing next service page")?
            .services
            .is_empty()
    );
    success(handle.submit(Action::RevokeService {
        service_id: id,
        expected_revision: 2,
    })?)
    .await?;
    assert_eq!(
        handle
            .snapshot()
            .selected_service
            .data
            .as_ref()
            .ok_or("missing revoked service")?
            .approval,
        ServiceApprovalState::Revoked
    );
    success(handle.logout()?).await?;
    assert!(handle.snapshot().services.data.is_none());
    assert!(handle.snapshot().selected_service.data.is_none());
    assert_eq!(
        core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    Ok(())
}

#[tokio::test]
async fn committed_service_response_after_logout_cannot_repopulate_another_generation() -> Result {
    let gate = Gate::new("/api/v3/services", "POST");
    let server = Server::start(Some(gate.clone())).await?;
    let (mut core, handle, create) = prepare(&server).await?;
    gate.arm();
    let writing = handle.submit(Action::CreateService { create })?;
    gate.entered().await?;
    let previous_generation = handle.snapshot().generation;
    let logout = handle.logout()?;
    wait_view(&handle, |view| view.generation > previous_generation).await?;
    assert!(handle.snapshot().services.data.is_none());
    gate.unblock();
    let late = done(writing).await?;
    assert_eq!(late.result.status, OperationStatus::Superseded);
    assert_eq!(late.result.remote_effect, RemoteEffect::Committed);
    success(logout).await?;
    assert!(handle.snapshot().services.data.is_none());
    assert!(handle.snapshot().selected_service.data.is_none());
    assert_eq!(
        core.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    Ok(())
}
