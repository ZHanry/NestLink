//! Both endpoint proofs, server issuance and local renewal form one supervised
//! round. Dropping an in-flight round stops the connection; no detached work.
use crate::{DeviceIdentity, Sdk, SdkError, native::NativeMediaEvidence};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_identity::{
    VerifiedPermit, digest, verify_device_action, verify_native_renewal, verify_permit,
};
use nestlink_protocol::{
    DeviceAction, DeviceActionClaims, SCHEMA_VERSION,
    api::RemoteView,
    native_renewal::{Envelope, Kind},
};
use nestlink_remote::{
    LeaseControl,
    native_renewal::{NativeExecutionFence, NativeRenewalPort},
};
use nestlink_session::{EndpointRole, StopReason};
use std::{future::Future, io, time::Duration};
use tokio::time::Instant;

/// Preparation runs only for an actual renewal round, after the host receives
/// an authenticated Offer. It must return actual owner fencing, never a probe
/// timestamp presented as execution currentness.
pub struct PreparedNativeRenewal {
    pub evidence: NativeMediaEvidence,
    pub execution: std::sync::Arc<dyn NativeExecutionFence>,
}
pub trait NativeRenewalSource: Send + Sync {
    fn prepare<'a>(
        &'a self,
        sdk: &'a Sdk,
        identity: &'a DeviceIdentity,
        current: &'a VerifiedPermit,
        role: EndpointRole,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<PreparedNativeRenewal, SdkError>> + Send + 'a>>;
}
pub(crate) struct Coordinator {
    port: NativeRenewalPort,
    current: VerifiedPermit,
    peer_key: [u8; 32],
    role: EndpointRole,
    sequence: std::sync::Arc<std::sync::atomic::AtomicU64>,
    completed: Option<([u8; 32], Vec<u8>, Instant)>,
}
struct RoundGuard {
    lease: LeaseControl,
    complete: bool,
}
impl Drop for RoundGuard {
    fn drop(&mut self) {
        if !self.complete {
            let _ = self.lease.stop(StopReason::Revoked);
        }
    }
}
async fn bounded<T>(
    deadline: Instant,
    future: impl Future<Output = Result<T, SdkError>>,
) -> Result<T, SdkError> {
    tokio::time::timeout_at(deadline, future)
        .await
        .map_err(|_| SdkError::Timeout)?
}
fn protected<T>(
    fence: &dyn NativeExecutionFence,
    op: impl FnOnce() -> Result<T, SdkError>,
) -> Result<T, SdkError> {
    let mut op = Some(op);
    let mut result = None;
    let mut calls = 0usize;
    fence.with_current(&mut || {
        calls = calls.saturating_add(1);
        if calls != 1 {
            return Err(io::Error::other("execution operation repeated"));
        }
        let op = op
            .take()
            .ok_or_else(|| io::Error::other("execution operation repeated"))?;
        result = Some(op());
        Ok(())
    })?;
    if calls != 1 {
        return Err(SdkError::Trust);
    }
    result.ok_or(SdkError::Trust)?
}
fn transcript(
    view: &RemoteView,
    old: &VerifiedPermit,
    account: String,
    device: String,
) -> Result<DeviceActionClaims, SdkError> {
    let c = old.claims();
    Ok(DeviceActionClaims {
        schema_version: SCHEMA_VERSION,
        action: DeviceAction::Renew as i32,
        deployment_id: c.deployment_id.clone(),
        security_epoch: c.security_epoch,
        account_id: account,
        device_id: device,
        resource_id: c.session_id.clone(),
        challenge: URL_SAFE_NO_PAD
            .decode(&view.nonce)
            .map_err(|_| SdkError::Invalid)?,
        payload_sha256: digest(
            &c.lease_sequence
                .checked_add(1)
                .ok_or(SdkError::Invalid)?
                .to_be_bytes(),
        )
        .to_vec(),
        expires_at_unix_ms: c.expires_at_unix_ms,
    })
}
impl Coordinator {
    pub(crate) fn new(
        port: NativeRenewalPort,
        current: VerifiedPermit,
        peer_key: [u8; 32],
        role: EndpointRole,
        sequence: std::sync::Arc<std::sync::atomic::AtomicU64>,
    ) -> Self {
        Self {
            port,
            current,
            peer_key,
            role,
            sequence,
            completed: None,
        }
    }
    pub(crate) fn current(&self) -> &VerifiedPermit {
        &self.current
    }
    fn envelope(
        &self,
        kind: Kind,
        round: [u8; 32],
        payload: Vec<u8>,
    ) -> Result<Envelope, SdkError> {
        let c = self.current.claims();
        Ok(Envelope {
            kind,
            session: *uuid::Uuid::parse_str(&c.session_id)
                .map_err(|_| SdkError::Invalid)?
                .as_bytes(),
            deployment: digest(c.deployment_id.as_bytes()),
            epoch: c.security_epoch,
            generation: c.connection_generation,
            old_sequence: c.lease_sequence,
            round,
            old_permit: digest(self.current.signed_envelope()),
            payload,
            signature: [0; 64],
        })
    }
    fn sign(
        &self,
        mut envelope: Envelope,
        identity: &DeviceIdentity,
        fence: &dyn NativeExecutionFence,
    ) -> Result<Envelope, SdkError> {
        envelope.signature = protected(fence, || {
            Ok(identity.identity.sign_native_renewal(&envelope)?)
        })?;
        Ok(envelope)
    }
    fn check(
        &self,
        envelope: &Envelope,
        kind: Kind,
        round: Option<[u8; 32]>,
    ) -> Result<(), SdkError> {
        let expected = self.envelope(kind, envelope.round, envelope.payload.clone())?;
        if envelope.kind != kind
            || envelope.session != expected.session
            || envelope.deployment != expected.deployment
            || envelope.epoch != expected.epoch
            || envelope.generation != expected.generation
            || envelope.old_sequence != expected.old_sequence
            || envelope.old_permit != expected.old_permit
            || round.is_some_and(|r| r != envelope.round)
        {
            return Err(SdkError::Trust);
        }
        verify_native_renewal(envelope, &self.peer_key)?;
        Ok(())
    }
    fn successor(&self, next: &VerifiedPermit) -> Result<(), SdkError> {
        let old = self.current.claims();
        let n = next.claims();
        let mut expected = n.clone();
        expected.lease_sequence = old.lease_sequence;
        expected.issued_at_unix_ms = old.issued_at_unix_ms;
        expected.expires_at_unix_ms = old.expires_at_unix_ms;
        if &expected != old
            || old.lease_sequence.checked_add(1) != Some(n.lease_sequence)
            || n.issued_at_unix_ms < old.issued_at_unix_ms
            || n.expires_at_unix_ms <= n.issued_at_unix_ms
            || next.issuer() != self.current.issuer()
        {
            return Err(SdkError::Trust);
        }
        Ok(())
    }
    async fn send(&self, envelope: &Envelope, deadline: Instant) -> Result<(), SdkError> {
        bounded(deadline, async {
            Ok(self.port.send(envelope.encode()?).await?)
        })
        .await
    }
    async fn receive(&mut self, deadline: Instant) -> Result<Envelope, SdkError> {
        bounded(deadline, async {
            Ok(Envelope::decode(&self.port.receive().await?)?)
        })
        .await
    }
    async fn view(
        &self,
        sdk: &Sdk,
        identity: &DeviceIdentity,
        deadline: Instant,
    ) -> Result<RemoteView, SdkError> {
        let c = self.current.claims();
        let view = bounded(deadline, sdk.remote(&c.session_id)).await?;
        if view.id != c.session_id
            || view.status != "approved"
            || view.controller_device_id != c.controller_device_id
            || view.host_device_id != c.host_device_id
            || view.connection_generation != c.connection_generation
            || view.lease_sequence != c.lease_sequence
            || view.policy_revision != c.policy_revision
            || view.permissions != c.permissions
            || view.paths != c.paths
        {
            return Err(SdkError::Trust);
        }
        let current = bounded(deadline, async {
            if self.role == EndpointRole::Controller {
                sdk.current_controller_permit(identity, &c.session_id).await
            } else {
                sdk.host_permit(identity, &c.session_id).await
            }
        })
        .await?;
        if current.claims() != c || current.issuer() != self.current.issuer() {
            return Err(SdkError::Trust);
        }
        Ok(view)
    }
    fn commit(
        &self,
        lease: &LeaseControl,
        next: VerifiedPermit,
        started: u64,
        evidence: &NativeMediaEvidence,
        fence: &dyn NativeExecutionFence,
    ) -> Result<(), SdkError> {
        self.successor(&next)?;
        let next_sequence = next.claims().lease_sequence;
        lease.renew_with_local_media_pending(
            next,
            started,
            self.current.claims().lease_sequence,
            &evidence.frozen,
            &evidence.local,
            self.role,
            self.role == EndpointRole::Controller,
            fence,
        )?;
        self.sequence
            .store(next_sequence, std::sync::atomic::Ordering::Release);
        Ok(())
    }
    fn validate_evidence(
        &self,
        lease: &LeaseControl,
        evidence: &NativeMediaEvidence,
        fence: &dyn NativeExecutionFence,
    ) -> Result<(), SdkError> {
        let now = lease.renewal_clock()?;
        protected(fence, || {
            evidence.bind(&self.current, self.role, now.unix_ms)?;
            Ok(())
        })
    }
    pub(crate) async fn step(
        &mut self,
        sdk: &Sdk,
        identity: &DeviceIdentity,
        lease: &LeaseControl,
        source: &dyn NativeRenewalSource,
    ) -> Result<VerifiedPermit, SdkError> {
        let remaining = lease.remaining()?;
        if self.role == EndpointRole::Controller && remaining > Duration::from_secs(10) {
            return Ok(self.current.clone());
        }
        let old_deadline = Instant::now() + remaining;
        let deadline = old_deadline
            .checked_sub(Duration::from_millis(500))
            .ok_or(SdkError::Timeout)?;
        let started = lease.renewal_clock()?.monotonic_ms;
        if deadline <= Instant::now() {
            return Err(SdkError::Timeout);
        }
        if self.role == EndpointRole::Controller {
            let mut guard = RoundGuard {
                lease: lease.clone(),
                complete: false,
            };
            let view = self.view(sdk, identity, deadline).await?;
            let prepared = bounded(
                deadline,
                source.prepare(sdk, identity, &self.current, self.role),
            )
            .await?;
            let evidence = &prepared.evidence;
            let fence = prepared.execution.as_ref();
            self.validate_evidence(lease, evidence, fence)?;
            let offer = self.sign(
                self.envelope(Kind::Offer, crate::random_bytes(), Vec::new())?,
                identity,
                fence,
            )?;
            self.send(&offer, deadline).await?;
            let host = self.receive(deadline).await?;
            self.check(&host, Kind::HostProof, Some(offer.round))?;
            let offer_digest = digest(&offer.encode()?);
            if host.payload[..32] != offer_digest {
                return Err(SdkError::Trust);
            }
            let host_account = uuid::Uuid::from_slice(&host.payload[32..48])
                .map_err(|_| SdkError::Invalid)?
                .to_string();
            let h = transcript(
                &view,
                &self.current,
                host_account,
                self.current.claims().host_device_id.clone(),
            )?;
            verify_device_action(&h, &self.peer_key, &host.payload[48..])?;
            self.validate_evidence(lease, evidence, fence)?;
            let controller = protected(fence, || {
                sdk.renewal_signature(identity, &view, &self.current)
            })?;
            let c = transcript(
                &view,
                &self.current,
                sdk.principal().ok_or(SdkError::SignIn)?.account_id.clone(),
                identity.device_id.clone(),
            )?;
            let controller_bytes = URL_SAFE_NO_PAD
                .decode(&controller)
                .map_err(|_| SdkError::Invalid)?;
            verify_device_action(&c, &identity.identity.public_key(), &controller_bytes)?;
            lease.remaining()?;
            // The only lost-response recovery point: unique coordinator, live
            // old lease, and both endpoint proofs have already been verified.
            let submit_deadline = deadline
                .checked_sub(Duration::from_secs(1))
                .ok_or(SdkError::Timeout)?;
            let issued = bounded(
                submit_deadline,
                sdk.submit_native_renewal(
                    &view.id,
                    view.lease_sequence
                        .checked_add(1)
                        .ok_or(SdkError::Invalid)?,
                    controller,
                    URL_SAFE_NO_PAD.encode(&host.payload[48..]),
                ),
            )
            .await;
            let next = match issued {
                Ok(next) => next,
                Err(SdkError::Timeout | SdkError::Transport(_)) => {
                    lease.remaining()?;
                    let next = bounded(deadline, sdk.current_controller_permit(identity, &view.id))
                        .await?;
                    self.successor(&next)?;
                    next
                }
                Err(error) => return Err(error),
            };
            lease.remaining()?;
            self.successor(&next)?;
            let mut payload = digest(&host.encode()?).to_vec();
            payload.extend_from_slice(next.signed_envelope());
            let grant = self.sign(
                self.envelope(Kind::Grant, offer.round, payload)?,
                identity,
                fence,
            )?;
            self.commit(lease, next.clone(), started, evidence, fence)?;
            // Guard and absolute timeout still enforce the OLD peer deadline
            // after the local LeaseControl has accepted a later expiry.
            self.send(&grant, deadline).await?;
            let applied = self.receive(deadline).await?;
            self.check(&applied, Kind::Applied, Some(offer.round))?;
            if applied.payload != digest(&grant.encode()?) {
                return Err(SdkError::Trust);
            }
            lease.acknowledge_native_renewal(next.claims().lease_sequence)?;
            self.current = next;
            guard.complete = true;
        } else {
            let wait = deadline.min(Instant::now() + Duration::from_millis(100));
            let offer = match self.receive(wait).await {
                Ok(value) => value,
                Err(SdkError::Timeout) => return Ok(self.current.clone()),
                Err(error) => return Err(error),
            };
            if let Some((grant, applied, until)) = &self.completed
                && offer.kind == Kind::Grant
                && digest(&offer.encode()?) == *grant
                && Instant::now() < *until
            {
                bounded(deadline, async {
                    Ok(self.port.send(applied.clone()).await?)
                })
                .await?;
                return Ok(self.current.clone());
            }
            let mut guard = RoundGuard {
                lease: lease.clone(),
                complete: false,
            };
            self.check(&offer, Kind::Offer, None)?;
            let view = self.view(sdk, identity, deadline).await?;
            let prepared = bounded(
                deadline,
                source.prepare(sdk, identity, &self.current, self.role),
            )
            .await?;
            let evidence = &prepared.evidence;
            let fence = prepared.execution.as_ref();
            self.validate_evidence(lease, evidence, fence)?;
            let host = protected(fence, || {
                sdk.renewal_signature(identity, &view, &self.current)
            })?;
            let mut payload = digest(&offer.encode()?).to_vec();
            payload.extend_from_slice(
                uuid::Uuid::parse_str(&sdk.principal().ok_or(SdkError::SignIn)?.account_id)
                    .map_err(|_| SdkError::Invalid)?
                    .as_bytes(),
            );
            payload.extend_from_slice(
                &URL_SAFE_NO_PAD
                    .decode(host)
                    .map_err(|_| SdkError::Invalid)?,
            );
            let proof = self.sign(
                self.envelope(Kind::HostProof, offer.round, payload)?,
                identity,
                fence,
            )?;
            self.send(&proof, deadline).await?;
            let grant = self.receive(deadline).await?;
            self.check(&grant, Kind::Grant, Some(offer.round))?;
            if grant.payload[..32] != digest(&proof.encode()?) {
                return Err(SdkError::Trust);
            }
            let next = verify_permit(&grant.payload[32..], &self.current.issuer())?
                .retain_remote_budget(&self.current)?;
            self.successor(&next)?;
            let applied = self.sign(
                self.envelope(
                    Kind::Applied,
                    offer.round,
                    digest(&grant.encode()?).to_vec(),
                )?,
                identity,
                fence,
            )?;
            self.commit(lease, next.clone(), started, evidence, fence)?;
            self.send(&applied, deadline).await?;
            self.completed = Some((digest(&grant.encode()?), applied.encode()?, old_deadline));
            self.current = next;
            guard.complete = true;
        }
        Ok(self.current.clone())
    }
}

#[cfg(test)]
mod callback_tests {
    use super::*;
    struct BadFence(usize);
    impl NativeExecutionFence for BadFence {
        fn with_current(&self, operation: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
            for _ in 0..self.0 {
                let _ = operation();
            }
            Ok(())
        }
    }
    #[test]
    fn skipped_or_duplicate_swallowed_callback_cannot_release_proof() {
        assert!(protected(&BadFence(0), || Ok(42)).is_err());
        assert!(protected(&BadFence(2), || Ok(42)).is_err());
        assert!(matches!(protected(&BadFence(1), || Ok(42)), Ok(42)));
    }
}

#[cfg(all(test, feature = "media-runtime-test-support"))]
mod tests;
