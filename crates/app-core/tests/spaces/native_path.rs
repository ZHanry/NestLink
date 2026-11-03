use super::*;
use nestlink_protocol::{Path, Permission, api::ApprovalChoice};
use nestlink_sdk::NetworkMonitor;
use std::{net::{Ipv4Addr, UdpSocket}, path::PathBuf, sync::Arc};

struct Fixture {
    _server: Server,
    owner_core: AppCore,
    controller_core: AppCore,
    owner: CoreHandle,
    controller: CoreHandle,
    owner_store: Arc<NativeNetworkFileStore>,
    controller_store: Arc<NativeNetworkFileStore>,
    directories: [PathBuf; 2],
    runtime: String,
    space_id: String,
    request_id: String,
    key: [u8; 32],
}

fn routed_ipv4() -> Result<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    // Select an OS route without sending test traffic to the documentation IP.
    socket.connect("192.0.2.1:9")?;
    match socket.local_addr()?.ip() {
        std::net::IpAddr::V4(address) if !address.is_loopback() => Ok(address),
        _ => Err("no non-loopback IPv4 route for the real native connection".into()),
    }
}

fn native_core(identity: DeviceIdentity, address: Ipv4Addr, directory: &std::path::Path)
    -> Result<(AppCore, Arc<NativeNetworkFileStore>)> {
    nestlink_platform_security::new_private_directory(directory)?;
    let store = Arc::new(NativeNetworkFileStore::open(directory)?);
    store.save(&NativeNetworkSettings { use_deployment_stun: false,
        private_network_prefixes: vec![format!("{address}/32")], ..Default::default() })?;
    let mut config = NativeSessionConfig::new(Arc::new(NetworkMonitor::start()?))
        .with_network_settings_store(store.clone())?;
    config.bind_address = (address, 0).into();
    config.supported_capabilities = vec!["vp8".into(), "opus".into()];
    Ok((AppCore::with_identity_and_native_session(Limits::default(), identity, config)?, store))
}

impl Fixture {
    async fn new(gate: Option<Arc<Gate>>) -> Result<Self> {
        let server = Server::start(gate).await?;
        let address = routed_ipv4()?;
        let directories = std::array::from_fn(|_| std::env::temp_dir().join(format!("nestlink-space-preview-{}", random_id())));
        let owner_identity = DeviceIdentity::generate();
        let owner_device = owner_identity.device_id.clone();
        let (owner_core, owner_store) = native_core(owner_identity, address, &directories[0])?;
        let owner = connect(&owner_core, &server).await?;
        enroll(&owner).await?;
        let account = success(owner.submit(Action::CreateAccount { username: "ordinary-controller".into(), password: password() })?).await?;
        let PublicOutput::Created { id: account_id } = account.result.output else { return Err("missing ordinary account".into()); };
        let space_id = create(&owner, "ordinary member native preparation").await?;
        join(&owner, &owner_device).await?;
        let mut issued = success(owner.submit(invite(&owner, Some(account_id), SpaceRole::Member))?).await?;
        let SensitiveMaterial::SpaceInvitation { invitation_id, token, .. } = issued.take_sensitive().ok_or("invitation missing")?;
        let controller_identity = DeviceIdentity::generate();
        let controller_device = controller_identity.device_id.clone();
        let (controller_core, controller_store) = native_core(controller_identity, address, &directories[1])?;
        let controller = controller_core.handle();
        success(controller.switch_server(server.config.clone())?).await?;
        success(controller.submit(Action::SignIn { username: "ordinary-controller".into(), password: password(), factor: None })?).await?;
        assert!(!controller.snapshot().principal.as_ref().unwrap().is_admin);
        enroll(&controller).await?;
        success(controller.submit(Action::Space { context: random_id(), action: SpaceAction::Accept {
            space_id: space_id.clone(), invitation_id, token,
        } })?).await?;
        join(&controller, &controller_device).await?;
        success(controller.submit(Action::RequestRemote { host_device_id: owner_device,
            permissions: vec![Permission::View as i32], path_mode: "direct_only".into(), access: RemoteAccess::LocalApproval,
        })?).await?;
        let pending = controller.snapshot().selected_request.data.as_ref().unwrap().clone();
        success(owner.submit(Action::ApproveRemote { request_id: pending.id.clone(),
            expected_nonce: pending.nonce.clone(), expected_policy_revision: pending.policy_revision,
            choice: ApprovalChoice { approved: true, permissions: vec![Permission::View as i32], paths: vec![Path::Direct as i32] },
        })?).await?;
        success(controller.submit(Action::IssueRemotePermit { request_id: pending.id.clone() })?).await?;
        success(owner.submit(Action::InspectRemote { request_id: pending.id.clone() })?).await?;
        select(&owner, &space_id).await?;
        select(&controller, &space_id).await?;
        // This fixture's independent server signer is the trusted channel.
        let key = server.network_authority_key;
        Ok(Self { _server: server, owner_core, controller_core, owner, controller, owner_store,
            controller_store, directories, runtime: random_id(), space_id, request_id: pending.id.clone(), key })
    }

    fn preview_action(&self, handle: &CoreHandle, key: [u8; 32]) -> Action {
        let snapshot = handle.snapshot();
        let details = selected(handle);
        let remote = snapshot.selected_request.data.as_ref().unwrap();
        Action::PreviewNativeSpace { request: NativeSpacePreviewRequest {
            runtime_id: self.runtime.clone(), context: snapshot.space_context.clone(), space_id: self.space_id.clone(),
            request_id: self.request_id.clone(), expected_connection_generation: remote.connection_generation,
            expected_space_revision: details.space.revision, expected_policy_epoch: details.space.policy_epoch,
            expected_network_revision: snapshot.native_network_revision, trusted_authority_key: key, mode: NativeSpaceMode::Direct,
        } }
    }

    async fn preview(&self, handle: &CoreHandle) -> Result<NativeSpacePreview> {
        success(handle.submit(self.preview_action(handle, self.key))?).await?;
        Ok(handle.snapshot().native_space_preview.data.as_ref().ok_or("preview missing")?.as_ref().clone())
    }

    fn confirmation(&self, preview: &NativeSpacePreview) -> Action {
        Action::ConfirmNativeSpace { confirmation: NativeSpaceConfirmation { runtime_id: self.runtime.clone(),
            context: preview.context.clone(), nonce: preview.nonce.clone(), node_ids: None } }
    }

    async fn finish(mut self) -> Result {
        assert_eq!(self.controller_core.shutdown(Duration::from_secs(5)).await, ShutdownState::Complete);
        assert_eq!(self.owner_core.shutdown(Duration::from_secs(5)).await, ShutdownState::Complete);
        drop(self.controller_core); drop(self.owner_core);
        drop(self.controller_store); drop(self.owner_store);
        for directory in self.directories { std::fs::remove_dir_all(directory)?; }
        Ok(())
    }
}

#[tokio::test]
async fn ordinary_member_one_use_preview_persists_exact_pair_and_starts_the_real_native_owner() -> Result {
    let f = Fixture::new(None).await?;
    let rejected = done(f.controller.submit(f.preview_action(&f.controller, [99; 32]))?).await?;
    assert_eq!(rejected.result.status, OperationStatus::Failed);
    assert!(f.controller.snapshot().native_space_preview.data.is_none());
    assert_eq!(selected(&f.controller).devices.len(), 1);
    let first = f.preview(&f.controller).await?;
    assert_eq!(first.installation_ids[0], f.controller.snapshot().installation.as_ref().unwrap().device_id);
    assert_eq!(first.roles, [SpaceRole::Member, SpaceRole::Owner]);
    let wrong_runtime = done(f.controller.submit(Action::ConfirmNativeSpace { confirmation: NativeSpaceConfirmation {
        runtime_id: random_id(), context: first.context.clone(), nonce: first.nonce.clone(), node_ids: None,
    } })?).await?;
    assert_eq!(wrong_runtime.result.status, OperationStatus::Failed);
    assert_eq!(f.controller.snapshot().native_network_revision, 0);
    assert_eq!(done(f.controller.submit(f.confirmation(&first))?).await?.result.status, OperationStatus::Failed);
    let before_cas = f.preview(&f.controller).await?;
    let snapshot = f.controller.snapshot();
    f.controller.configure_native_network(snapshot.generation, snapshot.native_network_revision, snapshot.native_network.clone()).await?;
    assert_eq!(done(f.controller.submit(f.confirmation(&before_cas))?).await?.result.status, OperationStatus::Failed);
    let controller_preview = f.preview(&f.controller).await?;
    assert_eq!(controller_preview.expires_at_unix_ms, first.expires_at_unix_ms);
    success(f.controller.submit(f.confirmation(&controller_preview))?).await?;
    let saved = f.controller_store.load()?;
    assert_eq!(saved, f.controller.snapshot().native_network);
    assert_eq!(saved.preparation.as_ref().unwrap().request_id, f.request_id);
    assert_eq!(saved.preparation.as_ref().unwrap().permit_sha256, controller_preview.permit_sha256);
    assert_eq!(done(f.controller.submit(f.confirmation(&controller_preview))?).await?.result.status, OperationStatus::Failed);
    let host_preview = f.preview(&f.owner).await?;
    success(f.owner.submit(f.confirmation(&host_preview))?).await?;
    assert_eq!(f.owner_store.load()?.space_path, saved.space_path);
    tokio::try_join!(
        success(f.controller.submit(Action::StartNativeSession { request_id: f.request_id.clone(), relay_node_id: None })?),
        success(f.owner.submit(Action::StartNativeSession { request_id: f.request_id.clone(), relay_node_id: None })?),
    )?;
    for handle in [&f.controller, &f.owner] {
        let snapshot = handle.snapshot();
        let session = snapshot.native_session.data.as_ref().ok_or("native session missing")?;
        assert_eq!(session.status, NativeSessionStatus::Connected);
        assert_eq!(session.path, Some(Path::Direct as i32));
    }
    let generation = controller_preview.connection_generation;
    tokio::try_join!(
        success(f.controller.submit(Action::StopNativeSession { request_id: f.request_id.clone(), connection_generation: generation })?),
        success(f.owner.submit(Action::StopNativeSession { request_id: f.request_id.clone(), connection_generation: generation })?),
    )?;
    f.finish().await
}

#[tokio::test]
async fn revoked_membership_readback_consumes_preview_without_saving_or_minting_a_replacement() -> Result {
    let gate = Gate::suffix("/preparation", "GET");
    let f = Fixture::new(Some(gate.clone())).await?;
    let preview = f.preview(&f.controller).await?;
    gate.arm_before();
    let confirming = f.controller.submit(f.confirmation(&preview))?;
    gate.entered().await?;
    let details = selected(&f.owner);
    let device = details.devices.iter().find(|device| device.installation_id == preview.installation_ids[0]).ok_or("controller device missing")?;
    success(f.owner.submit(scoped(&f.owner, SpaceAction::RemoveDevice { space_id: f.space_id.clone(), installation_id: device.installation_id.clone(),
        request: SpaceDeviceRemoval { expected_revision: details.space.revision, expected_membership_epoch: device.membership_epoch },
    }))?).await?;
    gate.unblock();
    let denied = done(confirming).await?;
    assert_eq!(denied.result.status, OperationStatus::Failed);
    assert_eq!(f.controller.snapshot().native_network_revision, 0);
    assert!(f.controller_store.load()?.preparation.is_none());
    assert!(f.controller.snapshot().native_space_preview.data.is_none());
    assert_eq!(done(f.controller.submit(f.confirmation(&preview))?).await?.result.status, OperationStatus::Failed);
    f.finish().await
}

#[tokio::test]
async fn preview_cannot_survive_reused_space_context_or_identity_change() -> Result {
    let f = Fixture::new(None).await?;
    let preview = f.preview(&f.controller).await?;
    success(f.controller.submit(Action::Space { context: preview.context.clone(), action: SpaceAction::Read {
        space_id: f.space_id.clone(), cursor: SpacePageCursor::default(),
    } })?).await?;
    assert!(f.controller.snapshot().native_space_preview.data.is_none());
    assert_eq!(done(f.controller.submit(f.confirmation(&preview))?).await?.result.status, OperationStatus::Failed);
    let before_logout = f.preview(&f.controller).await?;
    success(f.controller.logout()?).await?;
    success(f.controller.submit(Action::SignIn { username: "admin".into(), password: password(), factor: None })?).await?;
    assert!(f.controller.snapshot().native_space_preview.data.is_none());
    assert_eq!(done(f.controller.submit(f.confirmation(&before_logout))?).await?.result.status, OperationStatus::Failed);
    assert!(f.controller_store.load()?.preparation.is_none());
    f.finish().await
}
