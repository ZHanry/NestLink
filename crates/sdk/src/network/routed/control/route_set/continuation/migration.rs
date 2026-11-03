//! An explicit authenticated control slice on the existing standby owner.
//! It selects safe fresh-generation recovery; no inner rebind is claimed.
use super::*;
use nestlink_identity::digest;
use nestlink_protocol::network_migration::Binding;
use nestlink_transport_quic::migration::{self, CommittedMigration};

/// Only a completed pinned candidate transcript constructs this receipt.
/// The original owner must still stop/join input, media and business I/O before
/// the existing recovery coordinator obtains a new business generation.
pub struct AuthenticatedPathRecovery {
    proposal: Option<RouteSetRecoveryProposal>,
    candidate_index: usize,
    committed: CommittedMigration,
}
impl AuthenticatedPathRecovery {
    pub fn previous_path_epoch(&self) -> u64 {
        self.committed.binding().previous_path_epoch
    }
    pub fn next_path_epoch(&self) -> u64 {
        self.committed.binding().next_path_epoch
    }
    pub fn requires_fresh_business_admission(&self) -> bool {
        true
    }
}

impl ContinuousRouteSetSession {
    /// Both existing owners must explicitly drive this after their common
    /// standby is prepared. Capability exchange and all four signed phases use
    /// only that already pinned standby, including when the old path is silent.
    /// This does not turn the standby into a ChannelRuntime or reuse its node
    /// allocation for a newly proved business generation.
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
        let status = self.status()?;
        if self.migration_interrupted
            || self.committed_recovery.is_some()
            || candidate_index >= self.keys.len()
            || candidate_index == self.selected
            || status.policy.standby != Some(self.keys[candidate_index])
            || proposal.as_ref().is_some_and(|proposal| {
                status.policy.proposal.as_ref() != Some(&proposal.proposal)
                    || proposal.candidate_index != candidate_index
            })
        {
            return Err(SdkError::Trust.into());
        }
        self.route = self
            .route
            .refresh_current(sdk, local, &self.permit, peer_key)
            .await?;
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
        let deadline = self.route.deadline.min(proposal.as_ref().map_or(
            Instant::now()
                + Duration::from_millis(
                    nestlink_protocol::network_migration::MAX_CONTROL_LIFETIME_MS,
                ),
            |proposal| self.started + Duration::from_millis(proposal.proposal.deadline_ms()),
        ));
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
        self.migration_interrupted = true;
        let exchange = migration::exchange(
            &connection,
            nestlink_protocol::network::REMOTE_CAPABILITY_ALPN,
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
            && !cancel_is_stopped(&self.cancel)
            && self.channels.lease_control().remaining().is_ok()
        {
            self.shutdown(StopReason::TransportLost).await
        } else {
            let _ = self.channels.lease_control().stop(StopReason::Revoked);
            Err(SdkError::Trust.into())
        }
    }
}
