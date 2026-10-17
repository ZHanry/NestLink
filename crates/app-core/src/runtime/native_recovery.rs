//! Native replacement is an internal continuation of one stopped, proved
//! session. It cannot create local consent or a new authorization lifetime.
use super::*;
use nestlink_protocol::api::RemoteView;
use nestlink_sdk::NativeReconnectionConfig;

fn recoverable_stop(stopped: &NativeSessionStop, owner_pending: bool) -> bool {
    matches!(
        stopped.stop_reason,
        Some(NativeSessionStopReason::TransportLost | NativeSessionStopReason::NetworkChanged)
    ) && matches!(
        stopped.cleanup,
        Some(NativeSessionCleanup::Succeeded | NativeSessionCleanup::NotAttached)
    ) && stopped.failure.is_none()
        && !owner_pending
}

pub(super) fn retain_source(
    failed: NativeSession,
    endpoint: Box<NativeEndpoint>,
    context: NativeRecoveryContext,
    stopped: &NativeSessionStop,
    owner_pending: bool,
) -> Option<Box<NativeRecoverySource>> {
    if !recoverable_stop(stopped, owner_pending) {
        return None;
    }
    // All input/media/business cleanup has completed before this extraction.
    // The retained endpoint keeps the original network observer live, and the
    // retained session keeps its outside-stop observer live while Core waits
    // for the management client to return from an earlier operation.
    let budget = failed.channels.lease_control().reconnection_budget().ok()?;
    if budget.deadline() <= Instant::now()
        || context
            .deadline
            .is_some_and(|deadline| budget.deadline() > deadline)
    {
        return None;
    }
    Some(Box::new(NativeRecoverySource {
        key: stopped.key.clone(),
        failed,
        endpoint,
        budget,
        context,
    }))
}

fn same_server(left: &ApprovedServer, right: &ApprovedServer) -> bool {
    left.origin == right.origin
        && left.deployment_id == right.deployment_id
        && left.permit_issuer == right.permit_issuer
        && left.allow_loopback_http == right.allow_loopback_http
}

impl Actor {
    pub(super) fn native_network_idle(&self) -> bool {
        self.native_session_task.is_none()
            && self.native_session_key.is_none()
            && self.native_session_control.is_none()
            && self.native_recovery.is_none()
            && self.browser_host.is_none()
            && self
                .active
                .as_ref()
                .is_none_or(|active| active.native_request_id.is_none())
            && !self.shared.native_audio_cleanup_pending()
            && !self.shared.native_clipboard_cleanup_pending()
            && !self.shared.native_files_cleanup_pending()
    }

    pub(super) fn native_recovery_context_current(&self, context: &NativeRecoveryContext) -> bool {
        self.view.lifecycle == Lifecycle::Running
            && self.view.authentication == Authentication::SignedIn
            && self.view.principal.is_some()
            && !self.shared.closing.load(Ordering::Acquire)
            && !self.retire
            && self.boundary.is_none()
            && self.view.generation == context.core_generation
            && self.shared.generation.load(Ordering::Acquire) == context.core_generation
            && self.view.server.as_ref().is_some_and(|server| {
                server.origin == context.server.origin
                    && server.deployment_id == context.server.deployment_id
                    && server.approved_issuer == context.server.permit_issuer
                    && server.verified_health.is_some()
            })
            && self
                .sdk
                .as_ref()
                .is_none_or(|client| same_server(&client.server, &context.server))
    }

    pub(super) fn set_native_recovery_terminal(&mut self, failure: Option<Failure>) {
        if let Some(previous) = &self.view.native_session.data {
            let mut session = previous.as_ref().clone();
            session.status = if failure.is_some() {
                NativeSessionStatus::Failed
            } else {
                NativeSessionStatus::Stopped
            };
            session.host_view_authorized = false;
            session.stop_reason = self.local_stop_reason.or(session.stop_reason);
            session.failure = failure.clone();
            self.view.native_session.data = Some(Arc::new(session));
        }
        self.view.native_session.loading = None;
        self.view.native_session.error = failure;
        self.native_poll_deadline = None;
    }

    /// Returns true only after taking the one management client into a bounded
    /// recovery job. A network outage can wait here without a fresh deadline.
    pub(super) fn start_native_recovery(&mut self) -> bool {
        let Some(source) = self.native_recovery.as_ref() else {
            return false;
        };
        if !self.native_recovery_context_current(&source.context)
            || self.local_stop_reason.is_some()
        {
            if let Some(source) = self.native_recovery.take() {
                let _ = source.failed.control.stop(StopReason::ExplicitExit);
            }
            self.set_native_recovery_terminal(None);
            self.publish();
            return false;
        }
        if Instant::now() >= source.budget.deadline() {
            self.native_recovery = None;
            self.local_stop_reason = Some(NativeSessionStopReason::Expired);
            self.set_native_recovery_terminal(Some(Failure::local(FailureKind::PermitExpired)));
            self.local_stop_reason = None;
            self.publish();
            return false;
        }
        if !source
            .context
            .config
            .network()
            .subscribe()
            .borrow()
            .available
            || self.shared.native_audio_cleanup_pending()
            || self.shared.native_clipboard_cleanup_pending()
            || self.shared.native_files_cleanup_pending()
            || self.native_session_task.is_some()
            || self.browser_host.is_some()
        {
            return false;
        }
        let Some(identity) = self.identity.clone() else {
            self.native_recovery = None;
            self.set_native_recovery_terminal(Some(Failure::local(
                FailureKind::LocalIdentityRequired,
            )));
            self.publish();
            return false;
        };
        let Some(client) = self.sdk.take() else {
            return false;
        };
        let Some(source) = self.native_recovery.take() else {
            self.sdk = Some(client);
            return false;
        };
        let request_id = source.key.request_id.clone();
        let expected_connection_generation = Some(source.key.connection_generation);
        let core_generation = source.context.core_generation;
        let cancellation = Arc::new(AtomicBool::new(false));
        let fence = sdk_call::DispatchFence {
            generation: self.shared.generation.clone(),
            expected: core_generation,
            closing: self.shared.closing.clone(),
            cancelled: cancellation.clone(),
        };
        self.active = Some(Active {
            envelope: None,
            server: Some(client.server.clone()),
            section: None,
            cancelled: None,
            cancellation,
            secret: None,
            remote_revoke: None,
            native_request_id: Some(request_id.clone()),
            native_connection_generation: expected_connection_generation,
            service_host_runtime_id: None,
            future: Box::pin(async move {
                let result = recover_native_session(&client, &identity, *source, fence).await;
                Job::NativeEstablished {
                    client: Box::new(client),
                    request_id,
                    core_generation,
                    expected_connection_generation,
                    result,
                }
            }),
        });
        self.publish();
        true
    }
}

/// Reused for initial and successor permits. UI routes derive solely from
/// these authenticated claims after the SDK returns mutual endpoint proof.
pub(super) fn authorize_native_session(
    client: &Client,
    identity: &DeviceIdentity,
    config: &NativeSessionConfig,
    remote: &RemoteView,
    permit: &VerifiedPermit,
) -> Result<(NativeSessionKey, NativeSessionOptions), Failure> {
    let principal = client
        .sdk
        .principal()
        .ok_or_else(|| Failure::local(FailureKind::SignInRequired))?;
    let claims = permit.claims();
    let is_controller = remote.controller_device_id == identity.device_id;
    let is_host = remote.host_device_id == identity.device_id;
    let local_digest = if is_controller {
        &claims.controller_key_sha256
    } else {
        &claims.host_key_sha256
    };
    if is_controller == is_host
        || remote.status != "approved"
        || claims.connection_generation == 0
        || claims.lease_sequence == 0
        || claims.session_id != remote.id
        || claims.resource_id != remote.id
        || (is_controller && claims.account_id != principal.account_id)
        || claims.controller_device_id != remote.controller_device_id
        || claims.host_device_id != remote.host_device_id
        || claims.connection_generation != remote.connection_generation
        || claims.lease_sequence != remote.lease_sequence
        || claims.policy_revision != remote.policy_revision
        || claims.permissions != remote.permissions
        || claims.paths != remote.paths
        || remote.expires_at_unix_ms <= unix_millis().unwrap_or(u64::MAX)
        || claims.expires_at_unix_ms <= unix_millis().unwrap_or(u64::MAX)
        || claims.security_epoch != client.sdk.health().security_epoch
        || claims.deployment_id != client.server.deployment_id
        || local_digest.as_slice() != identity.identity.fingerprint().as_slice()
        || claims.required_capabilities.iter().any(|required| {
            !config
                .supported_capabilities
                .iter()
                .any(|supported| supported == required)
        })
    {
        return Err(Failure::local(FailureKind::Trust));
    }
    let permitted = |permission: Permission| claims.permissions.contains(&(permission as i32));
    let key = NativeSessionKey {
        request_id: remote.id.clone(),
        connection_generation: claims.connection_generation,
        lease_sequence: claims.lease_sequence,
        is_host,
        host_view_authorized: is_host && permitted(Permission::View),
        controller_view_authorized: is_controller && permitted(Permission::View),
        input_authorized: permitted(Permission::View) && permitted(Permission::Input),
        audio_authorized: permitted(Permission::Audio),
        file_read_authorized: permitted(Permission::FileRead),
        file_write_authorized: permitted(Permission::FileWrite),
        clipboard_read_authorized: permitted(Permission::ClipboardRead),
        clipboard_write_authorized: permitted(Permission::ClipboardWrite),
        path: 0,
    };
    let options = NativeSessionOptions {
        granted_permissions: claims
            .permissions
            .iter()
            .map(|permission| {
                Permission::try_from(*permission).map_err(|_| Failure::local(FailureKind::Invalid))
            })
            .collect::<Result<Vec<_>, _>>()?,
        supported_capabilities: config.supported_capabilities.clone(),
        local_paths: PathSet::from_wire(&claims.paths)
            .map_err(|_| Failure::local(FailureKind::Invalid))?,
    };
    Ok((key, options))
}

pub(super) async fn prove_endpoint(
    client: &Client,
    identity: &DeviceIdentity,
    config: &NativeSessionConfig,
    endpoint: &NativeEndpoint,
    options: NativeSessionOptions,
    fence: sdk_call::DispatchFence,
    deadline: Option<Instant>,
) -> Result<NativeSession, Failure> {
    fence.check()?;
    let (cancel_sender, cancel_receiver) = watch::channel(false);
    let establish = endpoint.establish(
        &client.sdk,
        identity,
        options,
        &[],
        config.stun_servers.clone(),
        cancel_receiver,
    );
    tokio::pin!(establish);
    let deadline_wait = async {
        match deadline {
            Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
            None => std::future::pending().await,
        }
    };
    tokio::select! {
        biased;
        result = &mut establish => result.map_err(map_establish_failure),
        _ = wait_for_fence_invalidation(fence) => {
            cancel_sender.send_replace(true);
            // Await the SDK's cleanup rather than dropping an establishment
            // future that may already own proved transport resources.
            let _ = establish.await;
            Err(Failure::local(FailureKind::NativeSessionCancelled))
        }
        _ = deadline_wait => {
            cancel_sender.send_replace(true);
            let _ = establish.await;
            Err(Failure::local(FailureKind::PermitExpired))
        }
    }
}

async fn recover_native_session(
    client: &Client,
    identity: &DeviceIdentity,
    source: NativeRecoverySource,
    fence: sdk_call::DispatchFence,
) -> Result<EstablishedNativeSession, Failure> {
    fence.check()?;
    let NativeRecoverySource {
        key,
        failed,
        endpoint,
        budget,
        mut context,
    } = source;
    let previous = budget.permit().clone();
    let deadline = budget.deadline();
    if Instant::now() >= deadline || !same_server(&client.server, &context.server) {
        return Err(Failure::local(FailureKind::PermitExpired));
    }
    let network = context.config.network().subscribe();
    let baseline = *network.borrow();
    if !baseline.available {
        return Err(Failure::local(FailureKind::NetworkChanged));
    }
    let cancelled = || {
        fence.check().is_err()
            || network.has_changed().is_err()
            || !network.borrow().available
            || network.borrow().generation != baseline.generation
    };
    let receipt = if key.is_host {
        client
            .sdk
            .reconnect_native_host(identity, &previous, &context.peer_key, failed, cancelled)
            .await
    } else {
        client
            .sdk
            .reconnect_native_controller(identity, &previous, &context.peer_key, failed, cancelled)
            .await
    };
    // The SDK has consumed the old session and extracted/capped its budget.
    drop(endpoint);
    let receipt = receipt.map_err(Failure::from)?;
    fence.check()?;
    if cancelled() {
        return Err(Failure::local(FailureKind::NetworkChanged));
    }
    receipt.remaining_ms().map_err(Failure::from)?;
    let next = receipt.permit();
    if next.claims().connection_generation
        != previous
            .claims()
            .connection_generation
            .checked_add(1)
            .ok_or_else(|| Failure::local(FailureKind::Trust))?
        || next.claims().lease_sequence
            != previous
                .claims()
                .lease_sequence
                .checked_add(1)
                .ok_or_else(|| Failure::local(FailureKind::Trust))?
        || next.digest() == previous.digest()
    {
        return Err(Failure::local(FailureKind::Trust));
    }
    let remote = tokio::time::timeout_at(deadline.into(), client.sdk.remote(&key.request_id))
        .await
        .map_err(|_| Failure::local(FailureKind::PermitExpired))?
        .map_err(Failure::from)?;
    fence.check()?;
    if cancelled() {
        return Err(Failure::local(FailureKind::NetworkChanged));
    }
    let (mut key, options) =
        authorize_native_session(client, identity, &context.config, &remote, next)?;
    let endpoint = client
        .sdk
        .reconnection_endpoint(
            &receipt,
            identity,
            &context.peer_key,
            NativeReconnectionConfig {
                bound: context.config.bind_address,
                stun_servers: context.config.stun_servers.clone(),
                address_policy: context
                    .config
                    .address_policy()
                    .map_err(|_| Failure::local(FailureKind::NativeSessionUnavailable))?,
                monitor: Some(context.config.network()),
            },
        )
        .map_err(Failure::from)?;
    let session = prove_endpoint(
        client,
        identity,
        &context.config,
        &endpoint,
        options,
        fence,
        Some(deadline),
    )
    .await?;
    key.path = session.candidate.path() as i32;
    context.deadline = Some(deadline);
    Ok(EstablishedNativeSession {
        session,
        key,
        endpoint: Box::new(endpoint),
        recovery: context,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stopped(reason: NativeSessionStopReason) -> NativeSessionStop {
        NativeSessionStop {
            key: NativeSessionKey {
                request_id: "00000000-0000-4000-8000-000000000001".into(),
                connection_generation: 4,
                lease_sequence: 9,
                is_host: true,
                host_view_authorized: true,
                controller_view_authorized: false,
                input_authorized: true,
                audio_authorized: true,
                file_read_authorized: true,
                file_write_authorized: true,
                clipboard_read_authorized: true,
                clipboard_write_authorized: true,
                path: 1,
            },
            stop_reason: Some(reason),
            stop_effects: None,
            cleanup: Some(NativeSessionCleanup::Succeeded),
            failure: None,
            recovery: None,
        }
    }

    #[test]
    fn cleanup_receipt_and_recoverable_reason_are_required_together() {
        for reason in [
            NativeSessionStopReason::TransportLost,
            NativeSessionStopReason::NetworkChanged,
        ] {
            let mut report = stopped(reason);
            assert!(recoverable_stop(&report, false));
            assert!(!recoverable_stop(&report, true));
            report.cleanup = Some(NativeSessionCleanup::Failed);
            assert!(!recoverable_stop(&report, false));
            report.cleanup = None;
            assert!(!recoverable_stop(&report, false));
            report.cleanup = Some(NativeSessionCleanup::Succeeded);
            report.failure = Some(Failure::local(FailureKind::NativeSessionUnavailable));
            assert!(!recoverable_stop(&report, false));
        }
        for reason in [
            NativeSessionStopReason::Revoked,
            NativeSessionStopReason::Expired,
            NativeSessionStopReason::ProtocolViolation,
            NativeSessionStopReason::PlatformChanged,
            NativeSessionStopReason::Suspended,
            NativeSessionStopReason::ClockInvalid,
            NativeSessionStopReason::UserCancelled,
            NativeSessionStopReason::ExplicitExit,
        ] {
            assert!(!recoverable_stop(&stopped(reason), false), "{reason:?}");
        }
    }
}
