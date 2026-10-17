//! Trusted deployment TURN credentials and both endpoint signatures for peers.
use super::*;
use nestlink_identity::turn::{
    credential_request_transcript, verify_turn_credentials, verify_turn_peer_binding,
    verify_turn_peer_signature,
};
use nestlink_protocol::{
    Path, SignedTurnCredentials, TurnCredentialsClaims, TurnPeerBindingClaims,
    turn::TURN_BINDING_BYTES,
};
use prost::Message;
use zeroize::Zeroize;

/// Owns the short-lived password without exposing it in diagnostic formatting.
pub struct TurnCredentials {
    claims: TurnCredentialsClaims,
}
impl Drop for TurnCredentials {
    fn drop(&mut self) {
        self.claims.password.zeroize();
    }
}
impl TurnCredentials {
    pub fn claims(&self) -> &TurnCredentialsClaims {
        &self.claims
    }
    pub fn authorize(&self, permit: &VerifiedPermit, now_ms: u64) -> Result<(), SdkError> {
        let c = &self.claims;
        let p = permit.claims();
        if now_ms < c.issued_at_unix_ms.saturating_sub(1000)
            || now_ms >= c.expires_at_unix_ms
            || now_ms >= p.expires_at_unix_ms
            || c.permit_sha256 != digest(&p.encode_to_vec())
            || c.lease_sequence != p.lease_sequence
            || c.connection_generation != p.connection_generation
            || c.session_id != p.session_id
            || c.deployment_id != p.deployment_id
            || c.security_epoch != p.security_epoch
            || !p.paths.contains(&(Path::Relay as i32))
        {
            return Err(SdkError::Trust);
        }
        Ok(())
    }
}
impl Sdk {
    pub async fn turn_endpoints(&self, node_id: &str) -> Result<TurnEndpointsView, SdkError> {
        self.required(
            Method::GET,
            &format!("{}/turn-endpoints", resource("nodes", node_id)?),
            None::<&()>,
        )
        .await
    }
    pub async fn configure_turn_endpoints(
        &self,
        node_id: &str,
        update: &TurnEndpointsUpdate,
    ) -> Result<TurnEndpointsView, SdkError> {
        update.config.validate()?;
        self.required(
            Method::PUT,
            &format!("{}/turn-endpoints", resource("nodes", node_id)?),
            Some(update),
        )
        .await
    }
    /// Allocation IDs are single-use. Retain one ID for live renewal; a network
    /// generation change requires a fresh ID and invalidates the old grant.
    pub async fn reserve_turn_credentials(
        &self,
        installation: &DeviceIdentity,
        permit: &VerifiedPermit,
        allocation_id: &str,
        network_generation: u64,
        now_ms: u64,
    ) -> Result<TurnCredentials, SdkError> {
        let p = permit.claims();
        if p.deployment_id != self.trust.deployment_id
            || p.security_epoch != self.health.security_epoch
            || !p.paths.contains(&(Path::Relay as i32))
        {
            return Err(SdkError::Trust);
        }
        super::signaling::other_endpoint(permit, installation)?;
        let principal = &self.login.as_ref().ok_or(SdkError::SignIn)?.principal;
        let mut request = TurnCredentialRequest {
            allocation_id: allocation_id.into(),
            device_id: installation.device_id.clone(),
            network_generation,
            signature: String::new(),
        };
        let transcript = credential_request_transcript(p, &principal.account_id, &request)?;
        request.signature = URL_SAFE_NO_PAD.encode(installation.identity.sign_action(&transcript)?);
        let mut signed: SignedTurnCredentials = self
            .required(
                Method::POST,
                &format!("{}/turn-credentials", resource("remote", &p.session_id)?),
                Some(&request),
            )
            .await?;
        let result = verify_turn_credentials(&signed, &self.trust.permit_issuer);
        signed.claims.zeroize();
        let credentials = TurnCredentials { claims: result? };
        let c = credentials.claims();
        if c.allocation_id != allocation_id
            || c.device_id != installation.device_id
            || c.temporary_identity != p.controller_device_id
            || c.network_generation != network_generation
            || c.request_sha256 != digest(&transcript.encode_to_vec())
            || c.expires_at_unix_ms > p.expires_at_unix_ms
            || (c.allow_loopback
                && !self.origin.host().is_some_and(|host| match host {
                    url::Host::Ipv4(ip) => ip.is_loopback(),
                    url::Host::Ipv6(ip) => ip.is_loopback(),
                    url::Host::Domain(name) => name == "localhost",
                }))
        {
            return Err(SdkError::Trust);
        }
        credentials.authorize(permit, now_ms)?;
        Ok(credentials)
    }
    pub async fn turn_binding_state(
        &self,
        installation: &DeviceIdentity,
        permit: &VerifiedPermit,
    ) -> Result<TurnBindingState, SdkError> {
        super::signaling::other_endpoint(permit, installation)?;
        let state: TurnBindingState = self
            .required(
                Method::GET,
                &format!(
                    "{}/turn-peers",
                    resource("remote", &permit.claims().session_id)?
                ),
                None::<&()>,
            )
            .await?;
        self.verify_turn_state(installation, permit, &state).await?;
        Ok(state)
    }
    pub async fn prove_turn_peers(
        &self,
        installation: &DeviceIdentity,
        permit: &VerifiedPermit,
        claims: &TurnPeerBindingClaims,
    ) -> Result<TurnBindingState, SdkError> {
        super::signaling::other_endpoint(permit, installation)?;
        validate_binding_permit(claims, permit)?;
        let proof = TurnPeerSubmission {
            device_id: installation.device_id.clone(),
            claims: claims.encode_to_vec(),
            signature: installation.identity.sign_turn_peer_binding(claims)?,
        };
        let state: TurnBindingState = self
            .required(
                Method::POST,
                &format!(
                    "{}/turn-peers",
                    resource("remote", &permit.claims().session_id)?
                ),
                Some(&proof),
            )
            .await?;
        self.verify_turn_state(installation, permit, &state).await?;
        if state
            .binding
            .as_ref()
            .is_none_or(|binding| binding.claims != proof.claims)
        {
            return Err(SdkError::Trust);
        }
        Ok(state)
    }
    async fn verify_turn_state(
        &self,
        installation: &DeviceIdentity,
        permit: &VerifiedPermit,
        state: &TurnBindingState,
    ) -> Result<(), SdkError> {
        for id in [&state.controller_allocation_id, &state.host_allocation_id]
            .into_iter()
            .flatten()
        {
            if !valid_id(id) {
                return Err(SdkError::Invalid);
            }
        }
        let Some(binding) = &state.binding else {
            return Ok(());
        };
        let claims: nestlink_protocol::TurnPeerBindingClaims =
            nestlink_protocol::decode_bounded(&binding.claims, TURN_BINDING_BYTES)?;
        validate_binding_permit(&claims, permit)?;
        if state.controller_allocation_id.as_deref() != Some(&claims.controller_allocation_id)
            || state.host_allocation_id.as_deref() != Some(&claims.host_allocation_id)
            || !matches!(binding.controller_signature.len(), 0 | 64)
            || !matches!(binding.host_signature.len(), 0 | 64)
            || binding.controller_signature.is_empty() && binding.host_signature.is_empty()
        {
            return Err(SdkError::Trust);
        }
        let peer = self.remote_peer_key(permit, installation).await?;
        let local = installation.identity.public_key();
        let (controller, host) = if installation.device_id == permit.claims().controller_device_id {
            (&local, &peer)
        } else {
            (&peer, &local)
        };
        if !binding.controller_signature.is_empty() {
            verify_turn_peer_signature(&binding.claims, controller, &binding.controller_signature)?;
        }
        if !binding.host_signature.is_empty() {
            verify_turn_peer_signature(&binding.claims, host, &binding.host_signature)?;
        }
        if !binding.controller_signature.is_empty() && !binding.host_signature.is_empty() {
            verify_turn_peer_binding(binding, controller, host)?;
        }
        Ok(())
    }
}
fn validate_binding_permit(
    b: &TurnPeerBindingClaims,
    permit: &VerifiedPermit,
) -> Result<(), SdkError> {
    b.validate()?;
    let p = permit.claims();
    if b.deployment_id != p.deployment_id
        || b.security_epoch != p.security_epoch
        || b.session_id != p.session_id
        || b.temporary_identity != p.controller_device_id
        || b.controller_device_id != p.controller_device_id
        || b.host_device_id != p.host_device_id
        || b.controller_key_sha256 != p.controller_key_sha256
        || b.host_key_sha256 != p.host_key_sha256
        || b.connection_generation != p.connection_generation
        || b.lease_sequence != p.lease_sequence
        || b.permit_sha256 != digest(&p.encode_to_vec())
        || b.expires_at_unix_ms > p.expires_at_unix_ms
        || !p.paths.contains(&(Path::Relay as i32))
    {
        return Err(SdkError::Trust);
    }
    Ok(())
}
