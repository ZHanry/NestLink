use super::{
    Error, PublicationContext, ServiceFlowPermit, ServicePublicationHandle, forward_streams,
    gate::rejected,
};
use nestlink_identity::{
    InstallationIdentity, digest,
    service_plane::{VerifiedServiceLease, verify_tunnel_challenge, verify_tunnel_proof},
    services::{decode_digest, definition_digest, local_target_digest},
};
use nestlink_protocol::{
    ErrorCode,
    api::{ServiceApprovalState, ServiceView},
    service_plane::*,
};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::watch,
};

/// Process-local owner of an explicit selection. It has no Deserialize/Clone,
/// never resolves a remote hostname, and revokes every dependent flow on Drop.
pub struct LocalTargetOwner {
    context: PublicationContext,
    original_view: ServiceView,
    target_id: String,
    target_sha256: [u8; 32],
    host_public_key: [u8; 32],
    protocol: String,
    address: SocketAddr,
    runtime_id: String,
    stopped: watch::Sender<bool>,
    used_opens: Mutex<HashMap<[u8; 32], Instant>>,
}
pub struct PreparedLocalTunnel {
    pub(super) flow: ServiceFlowPermit,
    pub(super) address: SocketAddr,
    pub(super) protocol: String,
    pub(super) stream_id: String,
    proof: ServiceTunnelProof,
    pub(super) challenge_deadline: Instant,
}
/// One consumed edge challenge for one pending visitor socket. Dropping it
/// releases its exact flow reservation; the nonce cannot authorize two opens.
pub struct PendingTunnelOpen {
    flow: ServiceFlowPermit,
    lease: VerifiedServiceLease,
    signed: SignedServiceTunnelChallenge,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    edge_public_key: [u8; 32],
    deadline: Instant,
}
fn wall() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| rejected(ErrorCode::LeaseExpired))?
        .as_millis()
        .try_into()
        .map_err(|_| rejected(ErrorCode::LeaseExpired).into())
}
impl LocalTargetOwner {
    /// Call only with the original revision-N view and target ID retained by the
    /// local chooser/SDK consent object. Never reconstruct this from N+1 or IPC.
    pub fn from_local_choice(
        context: PublicationContext,
        original_view: ServiceView,
        target_id: String,
        protocol: String,
        address: SocketAddr,
        host_public_key: [u8; 32],
    ) -> Result<Self, Error> {
        if original_view.approval == ServiceApprovalState::Revoked
            || definition_digest(&original_view.definition)?
                != decode_digest(&original_view.definition_sha256)?
        {
            return Err(Error::Target);
        }
        let target_sha256 = local_target_digest(&original_view, &target_id, &protocol, address)?;
        let (stopped, _) = watch::channel(false);
        Ok(Self {
            context,
            original_view,
            target_id,
            target_sha256,
            host_public_key,
            protocol,
            address,
            runtime_id: uuid::Uuid::new_v4().to_string(),
            stopped,
            used_opens: Mutex::new(HashMap::new()),
        })
    }
    pub fn target_id(&self) -> &str {
        &self.target_id
    }
    pub fn runtime_id(&self) -> &str {
        &self.runtime_id
    }
    pub fn target_sha256(&self) -> [u8; 32] {
        self.target_sha256
    }
    pub fn revoke(&self) {
        self.stopped.send_replace(true);
    }
    pub fn accepts(&self, lease: &VerifiedServiceLease) -> bool {
        let c = lease.claims();
        !*self.stopped.borrow()
            && c.deployment_id == self.context.deployment_id
            && c.security_epoch == self.context.security_epoch
            && c.policy_revision == self.context.policy_revision
            && c.service_id == self.original_view.id
            && lease.issuer() == self.context.service_lease_issuer
            && c.account_id == self.original_view.account_id
            && c.creator_login_id == self.original_view.management_session_id
            && c.choice_revision == self.original_view.revision
            && c.choice_revision.checked_add(1) == Some(c.service_revision)
            && c.definition == self.original_view.definition
            && c.target_id == self.target_id
            && c.target_sha256 == self.target_sha256
            && c.host_key_sha256 == digest(&self.host_public_key)
    }
    pub fn prepare(
        &self,
        publication: &ServicePublicationHandle,
        signed: &SignedServiceTunnelChallenge,
        edge_public_key: &[u8; 32],
        host: &InstallationIdentity,
    ) -> Result<PreparedLocalTunnel, Error> {
        let lease = publication.lease()?;
        self.prepare_for_lease(publication, &lease, signed, edge_public_key, host)
    }
    /// In-flight offers may name a prior still-valid lease while the control
    /// stream has already advanced. Accounting stays on the one current owner;
    /// the proof remains bound to the exact lease used by this visitor challenge.
    pub fn prepare_for_lease(
        &self,
        publication: &ServicePublicationHandle,
        lease: &VerifiedServiceLease,
        signed: &SignedServiceTunnelChallenge,
        edge_public_key: &[u8; 32],
        host: &InstallationIdentity,
    ) -> Result<PreparedLocalTunnel, Error> {
        let current = publication.lease()?;
        if !self.accepts(lease)
            || host.public_key() != self.host_public_key
            || current.binding() != lease.binding()
            || current.issuer() != lease.issuer()
            || lease.claims().lease_sequence > current.claims().lease_sequence
        {
            return Err(Error::Target);
        }
        let challenge = verify_tunnel_challenge(signed, lease, edge_public_key)?;
        let challenge_started = Instant::now();
        let now = wall()?;
        if now < challenge.issued_at_unix_ms || now >= challenge.expires_at_unix_ms {
            return Err(rejected(ErrorCode::LeaseExpired).into());
        }
        let peer = challenge.validate(lease.claims())?;
        let flow = publication.reserve_host(peer.ip(), self.stopped.subscribe())?;
        let proof = host.prove_service_tunnel(lease, signed, edge_public_key, &self.runtime_id)?;
        let key = digest(&signed.claims);
        let mut used = self.used_opens.lock().map_err(|_| Error::Target)?;
        let monotonic_now = Instant::now();
        used.retain(|_, end| *end > monotonic_now);
        if used.contains_key(&key) || used.len() >= 4096 {
            return Err(rejected(ErrorCode::ReplayRejected).into());
        }
        let end = challenge_started
            .checked_add(Duration::from_millis(challenge.expires_at_unix_ms - now))
            .filter(|end| *end > monotonic_now)
            .ok_or_else(|| rejected(ErrorCode::LeaseExpired))?;
        used.insert(key, end);
        Ok(PreparedLocalTunnel {
            flow,
            address: self.address,
            protocol: self.protocol.clone(),
            stream_id: challenge.stream_id,
            proof,
            challenge_deadline: end,
        })
    }
}
impl Drop for LocalTargetOwner {
    fn drop(&mut self) {
        self.revoke();
    }
}
impl PreparedLocalTunnel {
    pub(super) fn check_challenge_deadline(&self) -> Result<(), Error> {
        if Instant::now() >= self.challenge_deadline {
            return Err(rejected(ErrorCode::LeaseExpired).into());
        }
        Ok(())
    }
    pub fn proof(&self) -> &ServiceTunnelProof {
        &self.proof
    }
    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }
    /// The adapter must have verified its encrypted carrier against the leased
    /// edge identity. A stream's contents never select the local destination.
    pub async fn forward_stream<S>(self, carrier: S) -> Result<(), Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // HTTPS backends need an explicit TLS backend adapter; do not silently
        // send plaintext HTTP to an approved HTTPS destination.
        if !matches!(self.protocol.as_str(), "tcp" | "http") {
            return Err(Error::Target);
        }
        self.forward_using(carrier, |target| std::future::ready(Ok(target)))
            .await
    }
    /// The native host supplies a locally approved TLS adapter. The adapter
    /// wraps this already fixed TCP socket; it cannot choose a different IP.
    pub async fn forward_https<S, T, F, Fut>(self, carrier: S, tls: F) -> Result<(), Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
        T: AsyncRead + AsyncWrite + Unpin,
        F: FnOnce(TcpStream) -> Fut,
        Fut: std::future::Future<Output = std::io::Result<T>>,
    {
        if self.protocol != "https" {
            return Err(Error::Target);
        }
        self.forward_using(carrier, tls).await
    }
    async fn forward_using<S, T, F, Fut>(self, carrier: S, adapter: F) -> Result<(), Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
        T: AsyncRead + AsyncWrite + Unpin,
        F: FnOnce(TcpStream) -> Fut,
        Fut: std::future::Future<Output = std::io::Result<T>>,
    {
        let challenge_deadline = self.challenge_deadline;
        if Instant::now() >= challenge_deadline {
            return Err(rejected(ErrorCode::LeaseExpired).into());
        }
        self.flow.check_live()?;
        let connect = TcpStream::connect(self.address);
        let target = tokio::select! { biased;
            _=self.flow.wait_stopped()=>return Err(rejected(ErrorCode::PolicyRevoked).into()),
            _=tokio::time::sleep_until(challenge_deadline.into())=>return Err(rejected(ErrorCode::LeaseExpired).into()),
            result=tokio::time::timeout(Duration::from_secs(3),connect)=>result.map_err(|_| Error::Timeout("local TCP connect"))??,
        };
        if Instant::now() >= challenge_deadline {
            return Err(rejected(ErrorCode::LeaseExpired).into());
        }
        self.flow.check_live()?;
        let target = tokio::select! {biased;
            _=self.flow.wait_stopped()=>return Err(rejected(ErrorCode::PolicyRevoked).into()),
            _=tokio::time::sleep_until(challenge_deadline.into())=>return Err(rejected(ErrorCode::LeaseExpired).into()),
            target=adapter(target)=>target?,
        };
        self.check_challenge_deadline()?;
        self.flow.check_live()?;
        // The challenge gates local connection establishment. Connected flows
        // continue under their publication, node, idle and explicit stop owners.
        forward_streams(carrier, target, self.flow).await
    }
}
impl PendingTunnelOpen {
    pub fn lease(&self) -> &VerifiedServiceLease {
        &self.lease
    }
    pub fn new(
        flow: ServiceFlowPermit,
        edge: &nestlink_identity::nodes::NodeIdentity,
        peer: SocketAddr,
        transport: ServiceTunnelTransport,
    ) -> Result<Self, Error> {
        if !flow.is_edge() {
            return Err(Error::Target);
        }
        flow.check_live()?;
        let lease = flow.lease()?;
        let started = Instant::now();
        let issued_at_unix_ms = wall()?;
        let signed = edge.challenge_service_tunnel(
            &lease,
            uuid::Uuid::new_v4().to_string(),
            peer,
            transport,
            issued_at_unix_ms,
        )?;
        let c = verify_tunnel_challenge(&signed, &lease, &edge.public_key())?;
        let now = wall()?;
        if now < issued_at_unix_ms {
            return Err(rejected(ErrorCode::LeaseExpired).into());
        }
        let remaining = c
            .expires_at_unix_ms
            .checked_sub(now)
            .filter(|n| *n > 0)
            .ok_or_else(|| rejected(ErrorCode::LeaseExpired))?
            .min(SERVICE_RESOURCE_MS);
        let deadline = started
            .checked_add(Duration::from_millis(remaining))
            .filter(|end| *end > Instant::now())
            .ok_or_else(|| rejected(ErrorCode::LeaseExpired))?;
        Ok(Self {
            flow,
            lease,
            signed,
            deadline,
            issued_at_unix_ms,
            expires_at_unix_ms: c.expires_at_unix_ms,
            edge_public_key: edge.public_key(),
        })
    }
    pub fn challenge(&self) -> &SignedServiceTunnelChallenge {
        &self.signed
    }
    pub async fn wait_stopped(&self) {
        tokio::select! { biased;
            _=self.flow.wait_stopped()=>{},
            _=tokio::time::sleep_until(self.deadline.into())=>{},
        }
    }
    pub fn accept(
        self,
        host_public_key: &[u8; 32],
        proof: &ServiceTunnelProof,
    ) -> Result<ServiceFlowPermit, Error> {
        self.flow.check_live()?;
        let now = wall()?;
        if Instant::now() >= self.deadline
            || now < self.issued_at_unix_ms
            || now >= self.expires_at_unix_ms
        {
            return Err(rejected(ErrorCode::LeaseExpired).into());
        }
        verify_tunnel_proof(
            &self.lease,
            &self.signed,
            proof,
            host_public_key,
            &self.edge_public_key,
        )?;
        Ok(self.flow)
    }
}
