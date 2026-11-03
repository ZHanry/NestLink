//! Bilateral signed control on the original prepared standby. The unique
//! receipt permits the existing owner to rebind its original inner connection
//! or explicitly retire every carrier for independent application recovery.
use super::*;
use futures_util::FutureExt;
use nestlink_identity::digest;
use nestlink_protocol::network_migration::Binding;
use nestlink_protocol::network_migration::request::Request;
use nestlink_transport_quic::migration::{self, CommittedMigration};

/// Only a completed pinned candidate transcript constructs this receipt.
/// Only its original business owner can consume it. A retained-inner migration
/// preserves business generation and stream proof; the recovery alternative
/// first stops and joins every original business and physical owner.
pub struct AuthenticatedPathRecovery {
    proposal: Option<RouteSetRecoveryProposal>,
    candidate_index: usize,
    committed: CommittedMigration,
    retained_business: bool,
}
impl AuthenticatedPathRecovery {
    pub fn previous_path_epoch(&self) -> u64 {
        self.committed.binding().previous_path_epoch
    }
    pub fn next_path_epoch(&self) -> u64 {
        self.committed.binding().next_path_epoch
    }
    pub fn requires_fresh_business_admission(&self) -> bool {
        !self.retained_business
    }
}

impl ContinuousRouteSetSession {
    /// Drive this session's existing scheduler and the peer's reliable control
    /// request on its already prepared standby. Either endpoint can trigger;
    /// an otherwise healthy peer responds without a second local proposal.
    /// Local hard bounds, original authority and the unique signed proposer
    /// remain mandatory. File-only channels retain their proved generation;
    /// input/media/clipboard stop completely before application recovery may
    /// obtain fresh generation proof and a new independently bound carrier.
    pub async fn poll_with_path_migration(
        &mut self,
        sdk: &Sdk,
        local: &DeviceIdentity,
        peer_key: &[u8; 32],
        demand: bool,
    ) -> Result<RouteSetContinuationStatus, SessionEstablishError> {
        let status = self.poll(sdk, local, peer_key, demand).await?;
        self.drive_path_migration(sdk, local, peer_key, status, None)
            .await
    }

    /// An explicit local request on the exact original prepared member. The
    /// peer's ordinary poll_with_path_migration responds; it need not make a
    /// matching local request or independently prefer this route. Both owners
    /// still enforce their own original hard quality and authority bounds.
    pub async fn request_prepared_path_migration(
        &mut self,
        sdk: &Sdk,
        local: &DeviceIdentity,
        peer_key: &[u8; 32],
        candidate_index: usize,
    ) -> Result<RouteSetContinuationStatus, SessionEstablishError> {
        if self.migration_interrupted || self.committed_recovery.is_some() {
            return Err(SdkError::Trust.into());
        }
        let status = self.status()?;
        self.drive_path_migration(sdk, local, peer_key, status, Some(candidate_index))
            .await
    }

    async fn drive_path_migration(
        &mut self,
        sdk: &Sdk,
        local: &DeviceIdentity,
        peer_key: &[u8; 32],
        status: RouteSetContinuationStatus,
        request_index: Option<usize>,
    ) -> Result<RouteSetContinuationStatus, SessionEstablishError> {
        if status.policy.terminal.is_some() || self.committed_recovery.is_some() {
            return Ok(status);
        }
        if cancel_is_stopped(&self.cancel)
            || self.channels.lease_control().remaining().is_err()
            || !self
                .route
                .is_current_for(sdk, local, &self.permit, peer_key)
        {
            let _ = self.channels.lease_control().stop(StopReason::Revoked);
            return Err(SdkError::Trust.into());
        }
        let Some(slot) = self.standby.as_ref() else {
            return if request_index.is_some() {
                Err(SdkError::Trust.into())
            } else {
                Ok(status)
            };
        };
        let index = slot.index;
        if request_index.is_some_and(|requested| requested != index) {
            return Err(SdkError::Trust.into());
        }
        let initiate = status.recovery.is_some() || request_index.is_some();
        let connection = slot
            .transport
            .as_ref()
            .ok_or(SdkError::Trust)?
            .connection()
            .map_err(SdkError::ServiceIo)?
            .clone();
        // UNI requests are separate from the existing BI capability exchange
        // and four signed phases. Polling once never waits on a healthy idle
        // standby and never consumes any application/business stream.
        let incoming = match connection.accept_uni().now_or_never() {
            Some(Ok(stream)) => Some(stream),
            Some(Err(error)) => {
                let _ = self
                    .channels
                    .lease_control()
                    .stop(StopReason::TransportLost);
                return Err(SdkError::NodeQuic(error.into()).into());
            }
            None => None,
        };
        if incoming.is_none() && !initiate {
            return Ok(status);
        }
        if !self.scheduler.accepts_prepared_transition(
            self.now()?,
            self.keys[self.selected],
            self.keys[index],
        ) {
            let _ = self
                .channels
                .lease_control()
                .stop(StopReason::TransportLost);
            return Err(SdkError::Trust.into());
        }
        let expected = Request {
            permit: self.permit.digest(),
            transport_group: self.route.transport_group(),
            original_connection: self.original_connection,
            original_route: self.keys[self.selected].route_binding,
            candidate_route: self.keys[index].route_binding,
            previous_path_epoch: status.policy.epoch,
        };
        let mut deadline = self.route.deadline.min(
            Instant::now()
                + Duration::from_millis(
                    nestlink_protocol::network_migration::MAX_CONTROL_LIFETIME_MS,
                ),
        );
        if let Some(until) = self
            .channels
            .transport_owner_mut::<crate::network::routed::RemoteRouteOwner>()
            .and_then(|owner| owner.transport.held_path_loss_deadline())
        {
            deadline = deadline.min(until);
        }
        let lease = self.channels.lease_control();
        let mut cancel = self.cancel.clone();
        let mut stopped = lease.subscribe_stopped();
        self.migration_interrupted = true;
        lease.remaining()?;
        let requested = tokio::select! { biased;
            _ = cancelled(&mut cancel) => Err(SessionEstablishError::Cancelled),
            _ = stopped.changed() => Err(RemoteError::Stopped.into()),
            result = tokio::time::timeout_at(deadline,
                exchange_request(&connection, incoming, &expected, initiate)) =>
                result.unwrap_or_else(|_| Err(SdkError::Timeout.into())),
        };
        // A connection clone or request stream cannot survive into control
        // endpoint detach, otherwise its tracked release receipt would block.
        drop(connection);
        if let Err(error) = requested {
            let reason = match &error {
                SessionEstablishError::Contract(_) => StopReason::ProtocolViolation,
                SessionEstablishError::Sdk(SdkError::ServiceIo(error))
                    if error.kind() == io::ErrorKind::InvalidData =>
                {
                    StopReason::ProtocolViolation
                }
                SessionEstablishError::Cancelled
                | SessionEstablishError::Sdk(SdkError::Trust)
                | SessionEstablishError::Remote(RemoteError::Stopped) => StopReason::Revoked,
                _ => StopReason::TransportLost,
            };
            let _ = lease.stop(reason);
            return Err(error);
        }
        let receipt = self
            .authenticate_prepared(
                sdk,
                local,
                peer_key,
                index,
                status.recovery,
                true,
                Some(deadline),
            )
            .await?;
        if receipt.requires_fresh_business_admission() {
            // Existing input/platform handlers release held state at stop;
            // ChannelRuntime joins every old stream and discards its queues.
            // AppCore's existing recovery then proves a fresh generation and
            // attaches fresh media owners with the first keyframe required.
            self.retire_authenticated_path_recovery(sdk, local, peer_key, receipt)
                .await?;
        } else {
            self.commit_authenticated_path_migration(sdk, local, peer_key, receipt)
                .await?;
        }
        Ok(self.status()?)
    }

    /// Both existing owners must explicitly drive this after their common
    /// standby is prepared. Capability exchange and all four signed phases use
    /// only that already pinned standby, including when the old path is silent.
    /// Authentication alone does not move streams. Commit must transfer the
    /// actual standby carrier into the original proved business owner.
    pub async fn authenticate_path_recovery(
        &mut self,
        sdk: &Sdk,
        local: &DeviceIdentity,
        peer_key: &[u8; 32],
        proposal: &RouteSetRecoveryProposal,
    ) -> Result<AuthenticatedPathRecovery, SessionEstablishError> {
        let status = self.status()?;
        if self.migration_interrupted
            || self.committed_recovery.is_some()
            || status.policy.proposal.as_ref() != Some(&proposal.proposal)
            || self.now()? >= proposal.proposal.deadline_ms()
            || self.index(proposal.proposal.to())? != proposal.candidate_index
        {
            return Err(SdkError::Trust.into());
        }
        self.authenticate_prepared_path_recovery(
            sdk,
            local,
            peer_key,
            proposal.candidate_index,
            Some(proposal.clone()),
        )
        .await
    }

    /// Explicit local request on the exact already prepared standby. The peer
    /// must call the same API independently; this grants no unilateral switch.
    /// Automatic scheduling continues to use authenticate_path_recovery.
    pub async fn authenticate_prepared_path_recovery(
        &mut self,
        sdk: &Sdk,
        local: &DeviceIdentity,
        peer_key: &[u8; 32],
        candidate_index: usize,
        proposal: Option<RouteSetRecoveryProposal>,
    ) -> Result<AuthenticatedPathRecovery, SessionEstablishError> {
        self.authenticate_prepared(sdk, local, peer_key, candidate_index, proposal, false, None)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn authenticate_prepared(
        &mut self,
        sdk: &Sdk,
        local: &DeviceIdentity,
        peer_key: &[u8; 32],
        candidate_index: usize,
        proposal: Option<RouteSetRecoveryProposal>,
        request_started: bool,
        request_deadline: Option<Instant>,
    ) -> Result<AuthenticatedPathRecovery, SessionEstablishError> {
        let status = self.status()?;
        if (self.migration_interrupted && !request_started)
            || self.committed_recovery.is_some()
            || candidate_index >= self.keys.len()
            || candidate_index == self.selected
            || status.policy.standby != Some(self.keys[candidate_index])
            || !self.scheduler.accepts_prepared_transition(
                self.now()?,
                self.keys[self.selected],
                self.keys[candidate_index],
            )
            || proposal.as_ref().is_some_and(|proposal| {
                status.policy.proposal.as_ref() != Some(&proposal.proposal)
                    || proposal.candidate_index != candidate_index
            })
        {
            return Err(SdkError::Trust.into());
        }
        self.migration_interrupted = true;
        self.route = self
            .route
            .refresh_current(sdk, local, &self.permit, peer_key)
            .await?;
        if !self.route.member_authorized(self.selected) {
            let _ = self.channels.lease_control().stop(StopReason::Revoked);
            return Err(SdkError::Trust.into());
        }
        let candidate = self
            .route
            .candidate_for_admission(sdk, local, &self.permit, peer_key, candidate_index)
            .ok_or(SdkError::Trust)?;
        let slot = self
            .standby
            .as_ref()
            .filter(|slot| slot.index == candidate_index)
            .ok_or(SdkError::Trust)?;
        let connection = slot
            .transport
            .as_ref()
            .ok_or(SdkError::Trust)?
            .connection()
            .map_err(SdkError::ServiceIo)?
            .clone();
        let revocation = slot.revocation.clone().ok_or(SdkError::Trust)?;
        let route_binding = candidate.route_binding();
        let mut deadline = self.route.deadline.min(proposal.as_ref().map_or(
            Instant::now()
                + Duration::from_millis(
                    nestlink_protocol::network_migration::MAX_CONTROL_LIFETIME_MS,
                ),
            |proposal| self.started + Duration::from_millis(proposal.proposal.deadline_ms()),
        ));
        if let Some(request_deadline) = request_deadline {
            deadline = deadline.min(request_deadline);
        }
        if let Some(held_until) = self
            .channels
            .transport_owner_mut::<crate::network::routed::RemoteRouteOwner>()
            .and_then(|owner| owner.transport.held_path_loss_deadline())
        {
            deadline = deadline.min(held_until);
        }
        let binding = Binding {
            deployment: digest(self.route.deployment.as_bytes()),
            space: digest(self.route.pin.space_id.as_bytes()),
            session: digest(self.permit.claims().session_id.as_bytes()),
            permit: self.permit.digest(),
            path_grant: digest(
                &nestlink_protocol::network::GrantClaims::Path(
                    self.route.grants.path.claims().clone(),
                )
                .signing_message()?,
            ),
            transport_group: self.route.transport_group(),
            peers: self.route.grants.path.peers(),
            original_route: self.keys[self.selected].route_binding,
            candidate_route: route_binding,
            original_connection: self.original_connection,
            control_connection: migration::connection_binding(&connection)
                .map_err(SdkError::ServiceIo)?,
            business_generation: self.permit.claims().connection_generation,
            previous_path_epoch: status.policy.epoch,
            next_path_epoch: status
                .policy
                .epoch
                .checked_add(1)
                .ok_or(SdkError::Invalid)?,
            expires_at_unix_ms: self
                .route
                .grants
                .path
                .claims()
                .scope
                .expires_at_ms
                .min(self.permit.claims().expires_at_unix_ms),
        };
        let lease = self.channels.lease_control();
        let route = &self.route;
        let permit = &self.permit;
        let cancel = self.cancel.clone();
        let exchange = migration::exchange(
            &connection,
            nestlink_protocol::network_migration::packet::REMOTE_ALPN,
            binding,
            &local.identity,
            peer_key,
            self.cancel.clone(),
            deadline,
            || {
                if revocation.is_retired()
                    || cancel_is_stopped(&cancel)
                    || lease.remaining().is_err()
                    || !route.is_current_for(sdk, local, permit, peer_key)
                    || Instant::now() >= deadline
                {
                    Err(io::ErrorKind::PermissionDenied.into())
                } else {
                    Ok(())
                }
            },
        )
        .await;
        let committed = match exchange {
            Ok(receipt) => receipt,
            Err(error) => {
                // An ambiguous transport timeout can only use the established
                // safe-recovery path; a typed identity/authority failure stays
                // terminal. Neither path grants business I/O on standby.
                let reason = if error.downcast_ref::<io::Error>().is_some_and(|error| {
                    matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                            | io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::ConnectionReset
                    )
                }) || error.is::<tokio::time::error::Elapsed>()
                {
                    StopReason::TransportLost
                } else {
                    StopReason::Revoked
                };
                let _ = lease.stop(reason);
                return Err(SdkError::NodeQuic(error).into());
            }
        };
        let retained_business = self.channels.can_retain_business_for_path_migration()?;
        // This borrowed authentication future owns no control connection clone
        // during driver release. Keep the actual carrier owner in the standby.
        drop(connection);
        if !retained_business {
            // Full business teardown revokes standby raw I/O. First let the
            // unique Committed writer finish its real QUIC ACK, then join both
            // successful control drivers in role order within the SAME bound.
            // A denial/cancel/error keeps the existing immediate revoke path.
            let finished = self.standby
                .as_mut()
                .filter(|slot| slot.index == candidate_index)
                .and_then(|slot| slot.transport.as_mut())
                .ok_or(SdkError::Trust)?
                .finish_control_for_recovery(&committed, deadline)
                .await;
            if let Err(error) = finished {
                let _ = lease.stop(if error.kind() == io::ErrorKind::PermissionDenied {
                    StopReason::Revoked
                } else {
                    StopReason::TransportLost
                });
                return Err(SdkError::ServiceIo(error).into());
            }
        }
        // Refresh exact original authority again after signatures, before the
        // caller may retire a still-working business generation.
        self.route = match tokio::time::timeout_at(
            deadline,
            self.route
                .refresh_current(sdk, local, &self.permit, peer_key),
        )
        .await
        {
            Ok(Ok(current)) => current,
            _ => {
                let _ = lease.stop(StopReason::Revoked);
                return Err(SdkError::Trust.into());
            }
        };
        if cancel_is_stopped(&self.cancel)
            || lease.remaining().is_err()
            || !self.route.member_authorized(self.selected)
            || self
                .route
                .candidate_for_admission(sdk, local, &self.permit, peer_key, candidate_index)
                .is_none()
            || Instant::now() >= deadline
        {
            let _ = lease.stop(StopReason::Revoked);
            return Err(SdkError::Trust.into());
        }
        self.committed_recovery = Some(committed.transcript().proposal);
        self.migration_interrupted = false;
        Ok(AuthenticatedPathRecovery {
            proposal,
            candidate_index,
            committed,
            retained_business,
        })
    }

    /// Consume the receipt on its original owner, then use the same complete
    /// input/media/business/carrier teardown as ordinary safe recovery.
    pub async fn retire_authenticated_path_recovery(
        &mut self,
        sdk: &Sdk,
        local: &DeviceIdentity,
        peer_key: &[u8; 32],
        receipt: AuthenticatedPathRecovery,
    ) -> Result<StopReport, SessionEstablishError> {
        let binding = receipt.committed.binding();
        if self.committed_recovery != Some(receipt.committed.transcript().proposal)
            || binding.original_connection != self.original_connection
            || binding.permit != self.permit.digest()
            || binding.transport_group != self.route.transport_group()
            || binding.original_route != self.keys[self.selected].route_binding
            || receipt.candidate_index >= self.keys.len()
            || binding.candidate_route != self.keys[receipt.candidate_index].route_binding
        {
            return Err(SdkError::Trust.into());
        }
        if let Some(proposal) = receipt.proposal {
            self.retire_for_recovery(sdk, local, peer_key, &proposal)
                .await
        } else if self
            .route
            .is_current_for(sdk, local, &self.permit, peer_key)
            && self.route.member_authorized(self.selected)
            && !cancel_is_stopped(&self.cancel)
            && self.channels.lease_control().remaining().is_ok()
        {
            self.shutdown(StopReason::TransportLost).await
        } else {
            let _ = self.channels.lease_control().stop(StopReason::Revoked);
            Err(SdkError::Trust.into())
        }
    }

    /// Preserve the actual original business QUIC connection and streams.
    /// The unique candidate/control owner moves into the original carrier
    /// owner before any await; its old endpoint/pollers must release before
    /// rebind. A cancellation fences subsequent policy work and keeps all
    /// partially transferred owners available for complete session cleanup.
    pub async fn commit_authenticated_path_migration(
        &mut self,
        sdk: &Sdk,
        local: &DeviceIdentity,
        peer_key: &[u8; 32],
        receipt: AuthenticatedPathRecovery,
    ) -> Result<nestlink_transport_quic::routed::PathChange, SessionEstablishError> {
        let binding = receipt.committed.binding();
        if self.migration_interrupted
            || !receipt.retained_business
            || !self.channels.can_retain_business_for_path_migration()?
            || self.committed_recovery != Some(receipt.committed.transcript().proposal)
            || binding.original_connection != self.original_connection
            || binding.permit != self.permit.digest()
            || binding.transport_group != self.route.transport_group()
            || binding.original_route != self.keys[self.selected].route_binding
            || receipt.candidate_index >= self.keys.len()
            || binding.candidate_route != self.keys[receipt.candidate_index].route_binding
            || !self
                .route
                .is_current_for(sdk, local, &self.permit, peer_key)
            || !self.route.member_authorized(self.selected)
            || self
                .route
                .candidate_for_admission(
                    sdk,
                    local,
                    &self.permit,
                    peer_key,
                    receipt.candidate_index,
                )
                .is_none()
            || cancel_is_stopped(&self.cancel)
        {
            return Err(SdkError::Trust.into());
        }
        let from = self.keys[self.selected];
        let to = self.keys[receipt.candidate_index];
        let previous = binding.previous_path_epoch;
        let next = binding.next_path_epoch;
        let lease = self.channels.lease_control();
        lease.remaining()?;
        let slot = self
            .standby
            .as_mut()
            .filter(|slot| slot.index == receipt.candidate_index)
            .ok_or(SdkError::Trust)?;
        let owner = self
            .channels
            .transport_owner_mut::<crate::network::routed::RemoteRouteOwner>()
            .ok_or(SdkError::Trust)?;
        if slot.transport.is_none() || slot.revocation.is_none() {
            return Err(SdkError::Trust.into());
        }
        let candidate = slot.transport.take().ok_or(SdkError::Trust)?;
        if let Some(revocation) = slot.revocation.take() {
            owner
                .additional_revocations
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push(revocation);
        } else {
            return Err(SdkError::Trust.into());
        }
        if let Some(guardian) = slot.stop_guardian.take() {
            owner.guardians.push(guardian);
        }
        self.migration_interrupted = true;
        // Both authorities remain required throughout actual detach/rebind
        // and old-path drain. Cancellation leaves this requirement in place
        // until the fenced original owner finishes complete cleanup.
        if let Some(required) = &owner.required_members {
            required.fetch_or(
                1usize << receipt.candidate_index,
                std::sync::atomic::Ordering::AcqRel,
            );
        }
        let result = owner
            .transport
            .migrate(
                candidate,
                &receipt.committed,
                self.route
                    .deadline
                    .min(Instant::now() + Duration::from_secs(2)),
            )
            .await;
        let change = match result {
            Ok(change) => change,
            Err(error) => {
                let _ = lease.stop(if error.kind() == io::ErrorKind::PermissionDenied {
                    StopReason::Revoked
                } else {
                    StopReason::TransportLost
                });
                return Err(SdkError::ServiceIo(error).into());
            }
        };
        if let Some(required) = &owner.required_members {
            required.store(
                1usize << receipt.candidate_index,
                std::sync::atomic::Ordering::Release,
            );
        }
        lease.remaining()?;
        if cancel_is_stopped(&self.cancel)
            || !self
                .route
                .is_current_for(sdk, local, &self.permit, peer_key)
        {
            let _ = lease.stop(StopReason::Revoked);
            return Err(SdkError::Trust.into());
        }
        self.selected = receipt.candidate_index;
        self.standby = None;
        if let Err(error) = self
            .channels
            .rebind_quic_path_observation(self.originals[self.selected].binding.clone(), next)
        {
            let _ = lease.stop(StopReason::ProtocolViolation);
            return Err(error.into());
        }
        let decision = self.step(
            sdk,
            local,
            peer_key,
            ContinuationInput::AuthenticatedCommit {
                from,
                to,
                previous_epoch: previous,
                next_epoch: next,
            },
        )?;
        if decision.rejected.is_some() {
            let _ = lease.stop(StopReason::ProtocolViolation);
            return Err(SdkError::Trust.into());
        }
        // The real transport migration already joined the old receiver, hub,
        // driver/pollers and adjacency before returning this receipt.
        let mut retirements = Vec::new();
        for action in decision.actions {
            if let ContinuationAction::Retire(token) = action {
                if token.route() != from {
                    let _ = lease.stop(StopReason::ProtocolViolation);
                    return Err(SdkError::Trust.into());
                }
                retirements.push(token);
            } else if let ContinuationAction::Terminal(_) = action {
                let _ = lease.stop(StopReason::Revoked);
                return Err(SdkError::Trust.into());
            }
        }
        self.pending_retirements.retain(|pending| {
            if pending.token.route() == from {
                if !retirements.contains(&pending.token) {
                    retirements.push(pending.token.clone());
                }
                false
            } else {
                true
            }
        });
        for token in retirements {
            let acknowledged =
                self.step(sdk, local, peer_key, ContinuationInput::Retired(token))?;
            if acknowledged.rejected.is_some() {
                let _ = lease.stop(StopReason::ProtocolViolation);
                return Err(SdkError::Trust.into());
            }
        }
        self.active_feedback = None;
        self.committed_recovery = None;
        self.migration_interrupted = false;
        Ok(change)
    }
}

async fn exchange_request(
    connection: &quinn::Connection,
    incoming: Option<quinn::RecvStream>,
    expected: &Request,
    initiate: bool,
) -> Result<(), SessionEstablishError> {
    if let Some(mut receive) = incoming {
        let bytes = receive
            .read_to_end(nestlink_protocol::network_migration::request::MAX_BYTES)
            .await
            .map_err(|error| {
                SdkError::ServiceIo(io::Error::new(io::ErrorKind::InvalidData, error))
            })?;
        if Request::decode(&bytes)? != *expected {
            return Err(SdkError::Trust.into());
        }
    }
    if initiate {
        let mut send = connection
            .open_uni()
            .await
            .map_err(|error| SdkError::NodeQuic(error.into()))?;
        send.write_all(&expected.encode()?)
            .await
            .map_err(|error| SdkError::NodeQuic(error.into()))?;
        send.finish()
            .map_err(|error| SdkError::NodeQuic(error.into()))?;
    }
    Ok(())
}
