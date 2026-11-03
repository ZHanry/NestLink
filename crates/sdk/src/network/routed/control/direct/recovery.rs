//! Re-admit one exact direct-space successor after the original proved owner
//! has stopped. Storage persists and checks the signed parent on every GET.
use super::*;
use crate::ReconnectedPermit;
use nestlink_identity::reconnection;
use nestlink_protocol::api::NetworkRemotePathRequest;

impl VerifiedRemoteDirect {
    fn recovery_fingerprint(&self) -> Result<[u8; 32], SdkError> {
        let claims =
            |view| crate::network_management::decode_network_grant(view).map(|grant| grant.claims);
        Ok(reconnection::direct_recovery_fingerprint(
            &claims(&self.view.path)?,
            &claims(&self.view.connectivity)?,
            [
                &claims(&self.view.controller_membership)?,
                &claims(&self.view.host_membership)?,
            ],
        ))
    }
    /// The existing business receipt cannot choose another space or grant. Its
    /// exact signed choice and the full old chain determine both request IDs.
    pub async fn recover_for_permit(
        &self,
        sdk: &Sdk,
        local: &DeviceIdentity,
        peer: &[u8; 32],
        receipt: &ReconnectedPermit,
    ) -> Result<Self, SdkError> {
        if !self.bound_to(sdk, local, peer) {
            return Err(SdkError::Trust);
        }
        receipt.remaining_ms()?;
        reconnection::validate_successor(
            self.permit.claims(),
            receipt.permit().claims(),
            receipt.choice(),
        )?;
        let hash = self.recovery_fingerprint()?;
        let path = crate::network_management::decode_network_grant(&self.view.path)?;
        let path_claims = GrantClaims::decode_canonical(&path.claims)?;
        let request = NetworkRemotePathRequest {
            path_grant_id: reconnection::direct_recovery_id(
                self.permit.claims(),
                receipt.choice(),
                hash,
                1,
            )?,
            connectivity_grant_id: reconnection::direct_recovery_id(
                self.permit.claims(),
                receipt.choice(),
                hash,
                2,
            )?,
            controller_membership_grant_id: self.view.controller_membership.grant_id.clone(),
            host_membership_grant_id: self.view.host_membership.grant_id.clone(),
            expected_policy_epoch: path_claims.scope().policy_epoch,
            expires_at_unix_ms: path_claims.scope().expires_at_ms,
        };
        let controller = local.device_id == self.permit.claims().controller_device_id;
        let deadline = self
            .deadline
            .min(Instant::now() + Duration::from_millis(receipt.remaining_ms()?));
        // Missing and withdrawn paths intentionally share the server's 403.
        // Only the host can briefly wait for the controller's one transaction;
        // refusal never remains hidden until the original grant expires.
        let issuance_wait = deadline.min(Instant::now() + Duration::from_secs(1));
        let retryable = |error: &SdkError| {
            matches!(
                error,
                SdkError::Transport(_) | SdkError::Timeout | SdkError::BrowserTransport
            )
        };
        let prepare = async {
            if controller {
                // One immutable POST. If its response is lost or conflicts,
                // only the same GET is used; another slot is never allocated.
                match sdk
                    .issue_network_remote_path(
                        self.pin.space_id(),
                        &self.view.request_id,
                        request.clone(),
                    )
                    .await
                {
                    Ok(_) | Err(SdkError::Api(reqwest::StatusCode::CONFLICT, _)) => {}
                    Err(error) if retryable(&error) => {}
                    Err(error) => return Err(error),
                }
            }
            loop {
                if !self.bound_to(sdk, local, peer) {
                    return Err(SdkError::Trust);
                }
                receipt.remaining_ms()?;
                match sdk
                    .verified_network_remote_direct(
                        &self.pin,
                        local,
                        receipt.permit(),
                        peer,
                        &request.path_grant_id,
                    )
                    .await
                {
                    Ok(mut next) => {
                        let next_claims = GrantClaims::decode_canonical(
                            &crate::network_management::decode_network_grant(&next.view.path)?
                                .claims,
                        )?;
                        if next.membership_grant_ids() != self.membership_grant_ids()
                            || next.view.connectivity.grant_id != request.connectivity_grant_id
                            || next_claims.scope().policy_epoch != request.expected_policy_epoch
                            || next_claims.scope().expires_at_ms != request.expires_at_unix_ms
                            || next.view.controller_membership.claims
                                != self.view.controller_membership.claims
                            || next.view.host_membership.claims != self.view.host_membership.claims
                            || next.view.controller_membership.signature
                                != self.view.controller_membership.signature
                            || next.view.host_membership.signature
                                != self.view.host_membership.signature
                            || next.path_grant_id() == self.path_grant_id()
                        {
                            return Err(SdkError::Trust);
                        }
                        next.deadline = next.deadline.min(self.deadline).min(deadline);
                        return Ok(next);
                    }
                    Err(error) if retryable(&error) => {}
                    Err(SdkError::Api(
                        reqwest::StatusCode::FORBIDDEN | reqwest::StatusCode::NOT_FOUND,
                        _,
                    )) if !controller && Instant::now() < issuance_wait => {}
                    Err(error) => return Err(error),
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        };
        let next = tokio::time::timeout_at(deadline, prepare)
            .await
            .map_err(|_| SdkError::Timeout)??;
        if !self.bound_to(sdk, local, peer) {
            return Err(SdkError::Trust);
        }
        receipt.remaining_ms()?;
        Ok(next)
    }
}
