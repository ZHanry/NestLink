//! Idle-safe native recovery on an explicitly selected, freshly discovered relay.
//! Old channel handles stop permanently; consumers attach fresh platform/media
//! resources to the returned generation. Consent and local deadlines do not grow.
use crate::{
    DeviceIdentity, NativeReconnectionConfig, NativeRelayRoute, ReconnectedPermit, Sdk, SdkError,
    native::NativeSession,
};
use nestlink_identity::VerifiedPermit;
use nestlink_policy::PathSet;
use nestlink_protocol::{Path, Permission, valid_id};
use nestlink_remote::{ChannelRuntime, CleanupStatus, SessionLifecycle, SessionSetup};
use nestlink_session::{EndpointRole, Session, SessionBinding, StopReason};
use std::{future::Future, io};
use tokio::sync::watch;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryStage {
    Waiting,
    Cleaning,
    ExchangingProofs,
    Discovering,
    Reserving,
    Resolving,
    Connecting,
    Proving,
    Ready,
    Stopped(StopReason),
    Failed,
}
#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error("native recovery stopped: {0:?}")]
    Stopped(StopReason),
    #[error("native recovery failed: {0}")]
    Sdk(#[from] SdkError),
    #[error("native recovery cleanup failed: {0}")]
    Cleanup(#[from] nestlink_remote::RemoteError),
}
/// The node is an explicit local choice; its locations and key still come from
/// current signed discovery. Local permissions/capabilities remain independent.
pub struct RelayRecoveryConfig<'a> {
    pub endpoint: NativeReconnectionConfig<'a>,
    pub node_id: &'a str,
    pub permissions: Vec<Permission>,
    pub capabilities: Vec<String>,
    pub local_paths: PathSet,
    pub stop: watch::Receiver<Option<StopReason>>,
    pub cancel: watch::Receiver<bool>,
    pub progress: Option<watch::Sender<RecoveryStage>>,
}
/// Keeps the new endpoint's original network observer alive with its proved
/// session. Moving just the channel runtime out would invalidate that observer.
pub struct RecoveredNativeSession {
    session: NativeSession,
    receipt: ReconnectedPermit,
    endpoint: crate::native::NativeEndpoint,
}
impl RecoveredNativeSession {
    pub fn session(&self) -> &NativeSession {
        &self.session
    }
    pub fn session_mut(&mut self) -> &mut NativeSession {
        &mut self.session
    }
    pub fn channels(&self) -> &ChannelRuntime {
        &self.session.channels
    }
    pub fn channels_mut(&mut self) -> &mut ChannelRuntime {
        &mut self.session.channels
    }
    pub fn permit(&self) -> &VerifiedPermit {
        self.receipt.permit()
    }
    pub fn endpoint(&self) -> &crate::native::NativeEndpoint {
        &self.endpoint
    }
    /// Preserve endpoint ownership when passing a failed generation back in.
    pub fn into_parts(
        self,
    ) -> (
        NativeSession,
        crate::native::NativeEndpoint,
        ReconnectedPermit,
    ) {
        (self.session, self.endpoint, self.receipt)
    }
}
struct Signals {
    stop: watch::Receiver<Option<StopReason>>,
    cancel: watch::Receiver<bool>,
}
impl Signals {
    fn check(&self) -> Result<(), RecoveryError> {
        if self.stop.has_changed().is_err() {
            return Err(RecoveryError::Stopped(StopReason::Revoked));
        }
        if let Some(reason) = *self.stop.borrow() {
            return Err(RecoveryError::Stopped(reason));
        }
        if self.cancel.has_changed().is_err() || *self.cancel.borrow() {
            return Err(RecoveryError::Stopped(StopReason::ExplicitExit));
        }
        Ok(())
    }
    async fn interrupted(&mut self) -> RecoveryError {
        loop {
            let _ = self.stop.borrow_and_update();
            let _ = self.cancel.borrow_and_update();
            if let Err(error) = self.check() {
                return error;
            }
            tokio::select! {
                result = self.stop.changed() => if result.is_err() { return RecoveryError::Stopped(StopReason::Revoked); },
                result = self.cancel.changed() => if result.is_err() { return RecoveryError::Stopped(StopReason::ExplicitExit); },
            }
        }
    }
    fn guard<T>(
        &mut self,
        future: impl Future<Output = Result<T, RecoveryError>>,
    ) -> impl Future<Output = Result<T, RecoveryError>> {
        // Box before constructing the async state. Nesting several transport
        // and proof futures must fit the ordinary Windows application stack.
        let future = Box::pin(future);
        async move {
            self.check()?;
            let result = tokio::select! { biased;
                error = self.interrupted() => Err(error),
                result = future => result,
            };
            self.check()?;
            result
        }
    }
}
fn stage(progress: &Option<watch::Sender<RecoveryStage>>, value: RecoveryStage) {
    if let Some(sender) = progress {
        sender.send_replace(value);
    }
}
fn binding(
    permit: &VerifiedPermit,
    permissions: &[Permission],
    capabilities: &[String],
    local_paths: PathSet,
    media: Option<&crate::native::NativeMediaEvidence>,
    local_id: &str,
) -> Result<SessionBinding, SdkError> {
    let c = permit.claims();
    let role = if local_id == c.controller_device_id {
        EndpointRole::Controller
    } else if local_id == c.host_device_id {
        EndpointRole::Host
    } else {
        return Err(SdkError::Trust);
    };
    let now: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| SdkError::Trust)?
        .as_millis()
        .try_into()
        .map_err(|_| SdkError::Trust)?;
    let media = match (
        nestlink_protocol::media_authority::permit_formats(c)?,
        media,
    ) {
        (None, None) => None,
        (Some(_), Some(evidence)) => Some(evidence.bind(permit, role, now)?),
        _ => return Err(SdkError::Trust),
    };
    Ok(SessionBinding {
        media,
        deployment_id: c.deployment_id.clone(),
        security_epoch: c.security_epoch,
        session_id: c.session_id.clone(),
        account_id: c.account_id.clone(),
        controller_device_id: c.controller_device_id.clone(),
        host_device_id: c.host_device_id.clone(),
        controller_key_sha256: c
            .controller_key_sha256
            .as_slice()
            .try_into()
            .map_err(|_| SdkError::Trust)?,
        host_key_sha256: c
            .host_key_sha256
            .as_slice()
            .try_into()
            .map_err(|_| SdkError::Trust)?,
        resource_id: c.resource_id.clone(),
        policy_revision: c.policy_revision,
        connection_generation: c.connection_generation,
        capability_sha256: c
            .capability_sha256
            .as_slice()
            .try_into()
            .map_err(|_| SdkError::Trust)?,
        granted_permissions: permissions.to_vec(),
        supported_capabilities: {
            let mut supported = capabilities.to_vec();
            if !supported.iter().any(|value| value == nestlink_protocol::native_ice::CAPABILITY) {
                supported.push(nestlink_protocol::native_ice::CAPABILITY.into());
            }
            supported
        },
        local_paths,
    })
}
impl Sdk {
    /// Can run while the application's cloned sender and claimed receivers do
    /// business I/O. Idle stop supervision does not depend on receive polling.
    /// Performs one bounded recovery, and returns fresh generation handles.
    pub async fn recover_native_relay(
        &self,
        local: &DeviceIdentity,
        peer_key: &[u8; 32],
        failed: NativeSession,
        config: RelayRecoveryConfig<'_>,
    ) -> Result<RecoveredNativeSession, RecoveryError> {
        self.recover_native_relay_with_media(local, peer_key, failed, config, None)
            .await
    }
    pub async fn recover_native_relay_with_media(
        &self,
        local: &DeviceIdentity,
        peer_key: &[u8; 32],
        mut failed: NativeSession,
        config: RelayRecoveryConfig<'_>,
        media: Option<crate::native::NativeMediaEvidence>,
    ) -> Result<RecoveredNativeSession, RecoveryError> {
        let RelayRecoveryConfig {
            endpoint,
            node_id,
            permissions,
            capabilities,
            local_paths,
            stop,
            cancel,
            progress,
        } = config;
        stage(&progress, RecoveryStage::Waiting);
        let mut signals = Signals {
            stop: stop.clone(),
            cancel: cancel.clone(),
        };
        let result = async {
            let report = match signals
                .guard(async { Ok(failed.channels.wait_stopped().await?) })
                .await
            {
                Ok(report) => report,
                Err(error) => {
                    let reason = match &error {
                        RecoveryError::Stopped(reason) => *reason,
                        _ => StopReason::Revoked,
                    };
                    failed.channels.shutdown(reason).await?;
                    return Err(error);
                }
            };
            stage(&progress, RecoveryStage::Cleaning);
            if let CleanupStatus::Failed(kind) = report.cleanup {
                return Err(nestlink_remote::RemoteError::Io(io::Error::new(
                    kind,
                    "platform cleanup failed",
                ))
                .into());
            }
            if !matches!(
                report.reason,
                StopReason::TransportLost | StopReason::NetworkChanged
            ) {
                return Err(RecoveryError::Stopped(report.reason));
            }
            let budget = failed.channels.lease_control().reconnection_budget()?;
            drop(failed);
            if !valid_id(node_id)
                || !local_paths.contains(Path::Relay)
                || !budget
                    .permit()
                    .claims()
                    .paths
                    .contains(&(Path::Relay as i32))
            {
                return Err(SdkError::Trust.into());
            }
            // Check the supplied local permissions and required capabilities
            // before submitting consent for a successor generation.
            let clock = nestlink_remote::RuntimeClock::default();
            Session::activate(
                budget.permit().clone(),
                binding(
                    budget.permit(),
                    &permissions,
                    &capabilities,
                    local_paths,
                    media.as_ref(),
                    &local.device_id,
                )?,
                Path::Relay,
                0,
                clock.sample().map_err(nestlink_remote::RemoteError::from)?,
            )
            .map_err(SdkError::from)?;
            signals.check()?;
            let role = if local.device_id == budget.permit().claims().controller_device_id {
                EndpointRole::Controller
            } else {
                EndpointRole::Host
            };
            let expected = match role {
                EndpointRole::Controller => &budget.permit().claims().host_key_sha256,
                EndpointRole::Host => &budget.permit().claims().controller_key_sha256,
            };
            if nestlink_identity::digest(peer_key).as_slice() != expected {
                return Err(SdkError::Trust.into());
            }
            stage(&progress, RecoveryStage::ExchangingProofs);
            let receipt = match role {
                EndpointRole::Controller => {
                    let attempt = self.prepare_bounded_reconnection(local, &budget)?;
                    signals
                        .guard(async {
                            Ok(self
                                .coordinate_reconnection_controller(&attempt, peer_key, || false)
                                .await?)
                        })
                        .await?
                }
                EndpointRole::Host => {
                    signals
                        .guard(async {
                            Ok(self
                                .coordinate_reconnection_host_bounded(
                                    local,
                                    budget.permit(),
                                    peer_key,
                                    || false,
                                    Some(budget.deadline()),
                                )
                                .await?)
                        })
                        .await?
                }
            };
            signals.check()?;
            receipt.remaining_ms()?;
            stage(&progress, RecoveryStage::Discovering);
            // Both peers derive the same fresh UUID from the signed exchange.
            // Retrying an HTTP response uses that UUID, never a new reservation.
            let allocation_id = receipt.allocation_id(node_id)?;
            let discovery = signals
                .guard(async {
                    Ok(receipt
                        .bounded(self.discover_relay_nodes(local, receipt.permit()))
                        .await?)
                })
                .await?;
            if !discovery.nodes().iter().any(|n| n.node_id == node_id) {
                return Err(SdkError::Trust.into());
            }
            stage(&progress, RecoveryStage::Reserving);
            let allocation = signals
                .guard(async {
                    Ok(receipt
                        .bounded(self.reserve_relay_allocation(
                            local,
                            receipt.permit(),
                            &allocation_id,
                            node_id,
                        ))
                        .await?)
                })
                .await?;
            stage(&progress, RecoveryStage::Resolving);
            let (wss, quic) = signals
                .guard(async {
                    Ok(receipt
                        .bounded(self.discovered_node_routes(
                            &discovery,
                            local,
                            receipt.permit(),
                            &allocation,
                        ))
                        .await?)
                })
                .await?;
            let mut routes = Vec::new();
            if let Some(route) = &quic {
                routes.push(NativeRelayRoute::Quic(route));
            }
            if let Some(route) = &wss {
                routes.push(NativeRelayRoute::Wss(route));
            }
            let mut candidates = Vec::new();
            for route in &routes {
                candidates.extend(route.candidates(1)?);
            }
            let endpoint = self.reconnection_endpoint(&receipt, local, peer_key, endpoint)?;
            signals.check()?;
            stage(&progress, RecoveryStage::Connecting);
            let connection = signals
                .guard(async {
                    Ok(receipt
                        .bounded(async {
                            Ok(endpoint
                                .dial_native_with_relays(local, &routes, 1, candidates, cancel)
                                .await?)
                        })
                        .await?)
                })
                .await?;
            stage(&progress, RecoveryStage::Proving);
            let clock = receipt.runtime_clock()?;
            let session = Session::activate(
                receipt.permit().clone(),
                binding(
                    receipt.permit(),
                    &permissions,
                    &capabilities,
                    local_paths,
                    media.as_ref(),
                    &local.device_id,
                )?,
                connection.candidate.path(),
                0,
                clock.sample().map_err(nestlink_remote::RemoteError::from)?,
            )
            .map_err(SdkError::from)?;
            let session = signals
                .guard(async {
                    Ok(receipt
                        .bounded(async {
                            Ok(connection
                                .authorize(
                                    SessionSetup {
                                        session,
                                        path: Path::Relay,
                                        role,
                                        clock,
                                        lifecycle: SessionLifecycle::new(stop),
                                    },
                                    local,
                                    peer_key,
                                )
                                .await?)
                        })
                        .await?)
                })
                .await?;
            signals.check()?;
            receipt.remaining_ms()?;
            Ok(RecoveredNativeSession {
                session,
                receipt,
                endpoint,
            })
        }
        .await;
        stage(
            &progress,
            match &result {
                Ok(_) => RecoveryStage::Ready,
                Err(RecoveryError::Stopped(reason)) => RecoveryStage::Stopped(*reason),
                Err(_) => RecoveryStage::Failed,
            },
        );
        result
    }
}
