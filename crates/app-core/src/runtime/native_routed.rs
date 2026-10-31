//! Product ownership for the explicit signed original-group route. The actor
//! lends its one management Client for one continuous turn and receives the
//! same value back before its ordinary permit readback.
use super::*;
use nestlink_sdk::network::routed::{ContinuousRouteSetSession, RecoveredNetworkSession, PinnedNetworkSpace};
use nestlink_protocol::api::{NetworkRemoteRouteSetRequest, NetworkRemoteRouteSetMemberRequest, NetworkRemotePathRequest};

pub(super) struct RouteLifetime {
    _stop: watch::Sender<Option<StopReason>>,
    cancel: watch::Sender<bool>,
}
impl Drop for RouteLifetime {
    fn drop(&mut self) { self.cancel.send_replace(true); }
}
pub(super) enum NativeConnection {
    Legacy(Box<LegacyConnection>),
    Original { session: Box<ContinuousRouteSetSession>, lifetime: RouteLifetime },
    Recovered { session: Box<RecoveredNetworkSession>, _lifetime: RouteLifetime },
}
impl NativeConnection {
    pub(super) fn channels(&mut self) -> &mut ChannelRuntime {
        match self {
            Self::Legacy(session) => &mut session.channels,
            Self::Original { session, .. } => session.channels(),
            Self::Recovered { session, .. } => session.channels(),
        }
    }
    pub(super) fn control(&self) -> NativeSessionControl {
        match self {
            Self::Legacy(session) => session.control.clone(),
            Self::Original { session, .. } => session.control(),
            Self::Recovered { session, .. } => session.control(),
        }
    }
    pub(super) fn quality(&self) -> crate::NativePathQualityView {
        match self {
            Self::Legacy(session) => native_quality::selected_carrier(&session.candidate, session.uses_bilateral_ice()),
            _ => native_quality::selected_routed_carrier(),
        }
    }
    async fn wait_stopped(&mut self) -> Result<StopReport, SessionEstablishError> {
        match self {
            Self::Legacy(session) => session.wait_stopped().await.map_err(Into::into),
            Self::Original { session, .. } => session.wait_stopped().await,
            Self::Recovered { session, .. } => session.wait_stopped().await.map_err(Into::into),
        }
    }
    pub(super) async fn wait_owned(
        &mut self, requests: &mut mpsc::Receiver<RoutePollRequest>, context: &NativeRecoveryContext,
    ) -> Result<StopReport, SessionEstablishError> {
        let mut network = context.config.network().subscribe();
        let baseline = *network.borrow();
        let mut requests_open = true;
        loop {
            let control = self.control();
            if !network.borrow().available || network.borrow().generation != baseline.generation {
                let _ = control.stop(StopReason::NetworkChanged);
            }
            tokio::select! { biased;
                result = self.wait_stopped() => return result,
                changed = network.changed() => {
                    if changed.is_err() {
                        let _ = control.stop(StopReason::PlatformChanged);
                        return self.wait_stopped().await;
                    }
                },
                request = requests.recv(), if requests_open => match request {
                    Some(request) => self.poll_request(request, &context.peer_key).await,
                    None => requests_open = false,
                },
            }
        }
    }
    async fn poll_request(&mut self, request: RoutePollRequest, peer_key: &[u8;32]) {
        let Some(client) = take_client(&request.slot) else { return; };
        // Drop returns the sole Client on success, future cancellation or task
        // unwind, before completion is signaled to the actor's retained job.
        let loan = ClientLoan { client: Some(client), slot: request.slot.clone() };
        if let Some(client) = loan.client.as_ref()
            && request.fence.check().is_ok()
            && self.control().lease_remaining().is_ok()
            && let Self::Original { session, .. } = self
        {
            let deadline = tokio::time::Instant::now() + session.control().lease_remaining().unwrap_or_default().min(Duration::from_secs(3));
            let outcome = {
                let turn = session.poll(&client.sdk, &request.identity, peer_key, true);
                tokio::pin!(turn);
                tokio::select! { biased;
                    _ = wait_for_fence_invalidation(request.fence.clone()) => None,
                    result = tokio::time::timeout_at(deadline, &mut turn) => result.ok(),
                }
            };
            // A stale fence cannot cause a new recovery signature. The next
            // actual stop receipt still owns and joins interrupted standby I/O.
            if request.fence.check().is_err() {
                let _ = session.control().stop(StopReason::ExplicitExit);
            } else {
                match outcome {
                    Some(Ok(status)) => {
                        if let Some(proposal) = status.recovery {
                            let _ = session.retire_for_recovery(&client.sdk, &request.identity, peer_key, &proposal).await;
                        }
                    },
                    Some(Err(_)) | None => { let _ = session.control().stop(StopReason::Revoked); },
                }
            }
        }
        drop(loan);
        let _ = request.done.send(());
    }
}

type ClientSlot = Arc<Mutex<Option<Client>>>;
fn take_client(slot: &ClientSlot) -> Option<Client> {
    slot.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take()
}
struct ClientLoan { client: Option<Client>, slot: ClientSlot }
impl Drop for ClientLoan {
    fn drop(&mut self) {
        *self.slot.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = self.client.take();
    }
}
pub(super) struct RoutePollRequest {
    slot: ClientSlot,
    identity: Arc<DeviceIdentity>,
    fence: sdk_call::DispatchFence,
    done: oneshot::Sender<()>,
}
pub(super) async fn poll_owned(
    client: Client, identity: Arc<DeviceIdentity>, fence: sdk_call::DispatchFence,
    request: Option<mpsc::Sender<RoutePollRequest>>,
) -> Client {
    let Some(request) = request else { return client; };
    let slot = Arc::new(Mutex::new(Some(client)));
    let (done, completed) = oneshot::channel();
    // There can be one retained actor job. Never wait for queue capacity or
    // reset a lease/observer deadline because the owner is busy or stopped.
    if request.try_send(RoutePollRequest { slot: slot.clone(), identity, fence, done }).is_ok() {
        let _ = completed.await;
    }
    match take_client(&slot) {
        Some(client) => client,
        None => unreachable!("completed route poll must return its unique management Client"),
    }
}

fn retryable(error: &nestlink_sdk::SdkError) -> bool {
    matches!(error, nestlink_sdk::SdkError::Transport(_) | nestlink_sdk::SdkError::Timeout |
        nestlink_sdk::SdkError::Api(reqwest::StatusCode::FORBIDDEN | reqwest::StatusCode::CONFLICT, _))
}
#[allow(clippy::too_many_arguments)]
pub(super) async fn establish(
    client: &Client, identity: &DeviceIdentity, config: &NativeSessionConfig,
    permit: VerifiedPermit, peer_key: &[u8;32], key: &NativeSessionKey,
    options: NativeSessionOptions, fence: sdk_call::DispatchFence,
) -> Result<NativeConnection, Failure> {
    let local = config.route_set.as_ref().ok_or_else(|| Failure::local(FailureKind::Invalid))?;
    local.validate().map_err(|_| Failure::local(FailureKind::Invalid))?;
    if local.deployment_id != client.server.deployment_id || config.relay_node_id.is_some()
        || config.pcp_gateway.is_some() || !options.local_paths.contains(nestlink_protocol::Path::Relay)
    { return Err(Failure::local(FailureKind::Trust)); }
    let pin = PinnedNetworkSpace::new(local.space_id.clone(), local.authority_key).map_err(Failure::from)?;
    let started = Instant::now();
    let deadline = tokio::time::Instant::from_std(started + Duration::from_secs(8));
    let network = config.network().subscribe();
    let baseline = *network.borrow();
    let prepare = async {
        fence.check()?;
        let route = if key.is_host {
            loop {
                fence.check()?;
                match client.sdk.verified_network_remote_route_set(&pin, identity, &permit, peer_key, &key.request_id).await {
                    Ok(route) => break route,
                    Err(error) if retryable(&error) => tokio::time::sleep(Duration::from_millis(50)).await,
                    Err(error) => return Err(Failure::from(error)),
                }
            }
        } else {
            let policy = client.sdk.network_policy(&local.space_id).await.map_err(Failure::from)?;
            let authority = URL_SAFE_NO_PAD.decode(&policy.authority_public_key).map_err(|_| Failure::local(FailureKind::Trust))?;
            if authority.as_slice() != local.authority_key || policy.deployment_id != local.deployment_id
                || policy.space_id != local.space_id
            { return Err(Failure::local(FailureKind::Trust)); }
            let now = unix_millis().ok_or_else(|| Failure::local(FailureKind::Trust))?;
            let mut expires = permit.claims().expires_at_unix_ms.min(now.saturating_add(30_000));
            for id in [&local.controller_membership_grant_id, &local.host_membership_grant_id] {
                let view = client.sdk.network_membership_grant(&local.space_id, id).await.map_err(Failure::from)?;
                let signed = nestlink_sdk::network_management::decode_network_grant(&view).map_err(Failure::from)?;
                let claims = nestlink_protocol::network::GrantClaims::decode_canonical(&signed.claims)
                    .map_err(|_| Failure::local(FailureKind::Trust))?;
                expires = expires.min(claims.scope().expires_at_ms);
            }
            let discovery = client.sdk.discover_relay_nodes(identity,&permit).await.map_err(Failure::from)?;
            for id in &local.node_ids {
                let node = discovery.nodes().iter().find(|node| node.node_id == *id)
                    .ok_or_else(|| Failure::local(FailureKind::Trust))?;
                expires = expires.min(node.expires_at_unix_ms);
            }
            let mut allocations = [nestlink_auth::random_id(), nestlink_auth::random_id()];
            allocations.sort();
            let request = NetworkRemoteRouteSetRequest {
                set_id: key.request_id.clone(),
                path: NetworkRemotePathRequest {
                    connectivity_grant_id: nestlink_auth::random_id(), path_grant_id: nestlink_auth::random_id(),
                    controller_membership_grant_id: local.controller_membership_grant_id.clone(),
                    host_membership_grant_id: local.host_membership_grant_id.clone(),
                    expected_policy_epoch: policy.policy_epoch, expires_at_unix_ms: expires,
                },
                members: [0,1].map(|index| NetworkRemoteRouteSetMemberRequest {
                    allocation_id: allocations[index].clone(), transit_grant_id: nestlink_auth::random_id(), node_id: local.node_ids[index].clone(),
                }), device_id: identity.device_id.clone(), signature: String::new(),
            };
            loop {
                fence.check()?;
                match client.sdk.reserve_verified_network_remote_route_set(&pin,identity,&permit,peer_key,request.clone()).await {
                    Ok(route) => break route,
                    Err(error) if retryable(&error) => {
                        if let Ok(route) = client.sdk.verified_network_remote_route_set(&pin,identity,&permit,peer_key,&key.request_id).await { break route; }
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    },
                    Err(error) => return Err(Failure::from(error)),
                }
            }
        };
        // A same-space valid set is insufficient if it differs from local
        // explicit node intent; the authenticated SDK checks membership/keys.
        if route.candidates().iter().zip(&local.node_ids).any(|(candidate,id)| candidate.node().node_id != *id)
            || route.membership_grant_ids() != [local.controller_membership_grant_id.as_str(), local.host_membership_grant_id.as_str()]
        {
            return Err(Failure::local(FailureKind::Trust));
        }
        let media = native_recovery::prepare_media(client, identity, config, &permit, &fence).await?;
        Ok((route,media))
    };
    let (route, media) = tokio::time::timeout_at(deadline,prepare).await
        .map_err(|_| Failure::local(FailureKind::Timeout))??;
    fence.check()?;
    if !baseline.available || !network.borrow().available || network.borrow().generation != baseline.generation {
        return Err(Failure::local(FailureKind::NetworkChanged));
    }
    let (stop_tx, stop) = watch::channel(None);
    let (cancel_tx, cancel) = watch::channel(false);
    let lifetime = RouteLifetime { _stop: stop_tx, cancel: cancel_tx };
    let policy = config.address_policy().map_err(|_| Failure::local(FailureKind::Invalid))?;
    let connect = client.sdk.connect_continuing_network_remote_route_native(route,0,config.bind_address,
        identity,peer_key,permit,options,media,&policy,stop,cancel,deadline);
    tokio::pin!(connect);
    let session = tokio::select! { biased;
        result = &mut connect => result.map_err(map_establish_failure)?,
        _ = wait_for_fence_invalidation(fence.clone()) => {
            lifetime.cancel.send_replace(true);
            if let Ok(mut session) = connect.await { let _ = session.shutdown(StopReason::ExplicitExit).await; }
            return Err(Failure::local(FailureKind::NativeSessionCancelled));
        },
    };
    if !network.borrow().available || network.borrow().generation != baseline.generation {
        let mut session = session;
        let _ = session.shutdown(StopReason::NetworkChanged).await;
        return Err(Failure::local(FailureKind::NetworkChanged));
    }
    Ok(NativeConnection::Original { session: Box::new(session), lifetime })
}

pub(super) async fn recover(
    client: &Client, identity: &DeviceIdentity, session: Box<ContinuousRouteSetSession>,
    old_lifetime: RouteLifetime, mut context: NativeRecoveryContext, fence: sdk_call::DispatchFence,
) -> Result<EstablishedNativeSession, Failure> {
    fence.check()?;
    let network = context.config.network().subscribe();
    let baseline = *network.borrow();
    if !baseline.available { return Err(Failure::local(FailureKind::NetworkChanged)); }
    let source = tokio::select! { biased;
        _ = wait_for_fence_invalidation(fence.clone()) => return Err(Failure::local(FailureKind::NativeSessionCancelled)),
        source = (*session).into_recovery_source(&client.sdk,identity,&context.peer_key,None) => source.map_err(map_establish_failure)?,
    };
    let deadline = source.deadline();
    let previous = source.permit().clone();
    let options = NativeSessionOptions {
        granted_permissions: previous.claims().permissions.iter().map(|permission|
            Permission::try_from(*permission).map_err(|_| Failure::local(FailureKind::Trust)))
            .collect::<Result<Vec<_>,_>>()?,
        supported_capabilities: context.config.supported_capabilities.clone(),
        local_paths: PathSet::from_wire(&previous.claims().paths).map_err(|_| Failure::local(FailureKind::Trust))?,
    };
    let media = tokio::time::timeout_at(deadline.into(),native_recovery::prepare_media(client,identity,&context.config,&previous,&fence)).await
        .map_err(|_| Failure::local(FailureKind::PermitExpired))??;
    fence.check()?;
    if !network.borrow().available || network.borrow().generation != baseline.generation {
        return Err(Failure::local(FailureKind::NetworkChanged));
    }
    let (stop_tx,stop) = watch::channel(None);
    let (cancel_tx,cancel) = watch::channel(false);
    let lifetime = RouteLifetime { _stop: stop_tx, cancel: cancel_tx };
    let recovery = client.sdk.recover_network_route_set(identity,&context.peer_key,source,
        nestlink_sdk::network::routed::RouteSetRecoveryConfig {
            bind: context.config.bind_address,
            address_policy: context.config.address_policy().map_err(|_| Failure::local(FailureKind::Invalid))?,
            permissions: options.granted_permissions, capabilities: options.supported_capabilities,
            local_paths: options.local_paths, stop, cancel, media,
        });
    tokio::pin!(recovery);
    let result = tokio::select! { biased;
        result = &mut recovery => result,
        _ = wait_for_fence_invalidation(fence.clone()) => {
            lifetime.cancel.send_replace(true);
            recovery.await
        },
        _ = wait_network_change(network.clone(),baseline.generation) => {
            lifetime.cancel.send_replace(true);
            recovery.await
        },
    };
    drop(old_lifetime);
    let mut session = result.map_err(|_| Failure::local(FailureKind::NativeSessionUnavailable))?;
    let remote = match tokio::time::timeout_at(deadline.into(),client.sdk.remote(&previous.claims().session_id)).await {
        Ok(Ok(remote)) if fence.check().is_ok() && network.borrow().available
            && network.borrow().generation == baseline.generation => remote,
        _ => { let _ = session.shutdown(StopReason::ExplicitExit).await; return Err(Failure::local(FailureKind::NativeSessionCancelled)); },
    };
    let authorized = native_recovery::authorize_native_session(client,identity,&context.config,&remote,session.permit());
    let (mut key,_) = match authorized {
        Ok(value) => value,
        Err(error) => { let _ = session.shutdown(StopReason::Revoked).await; return Err(error); },
    };
    key.path = nestlink_protocol::Path::Relay as i32;
    context.deadline = Some(deadline);
    Ok(EstablishedNativeSession { session: NativeConnection::Recovered { session: Box::new(session), _lifetime: lifetime }, key, recovery: context })
}

async fn wait_network_change(mut network: watch::Receiver<nestlink_platform_network::NetworkState>, generation: u64) {
    loop {
        if !network.borrow().available || network.borrow().generation != generation { return; }
        if network.changed().await.is_err() { return; }
    }
}
