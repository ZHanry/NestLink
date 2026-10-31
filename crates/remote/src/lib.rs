//! End-to-end native proof and lease-gated channels, independent of QUIC/TLS/WSS.
use nestlink_identity::{InstallationIdentity, VerifiedPermit, verify_endpoint_proof};
pub mod audio;
pub mod clipboard;
pub mod files;
pub mod input;
mod lifecycle;
mod path_observation;
pub use nestlink_connectivity::observation::{
    BusinessThroughputWindow, PacketLossWindow, PathObservationBinding, PathObservationSnapshot,
};
pub use path_observation::PathObservation;
pub mod native_renewal;
mod queues;
pub mod quic;
pub mod upload;
pub mod video;
pub use lifecycle::{
    CleanupStatus, LeaseControl, NetworkBinding, ReconnectionBudget, SessionLifecycle, StopHandler,
    StopReport,
};
use nestlink_protocol::{
    CONTROL_BYTES, ContractError, EndpointProofClaims, NativeProof, Path, Permission,
    decode_bounded,
};
use nestlink_session::{ClockSample, EndpointRole, Session, StopEffects, StopReason};
use nestlink_transport_stream::{Channel, Frame, read_frame, write_frame};
use prost::Message;
pub use queues::{
    ChannelReceiver, ChannelRuntime, ChannelSender, DeliveryGuard, ExternalChannelRuntime,
    ExternalDataChannelPort, ExternalDataEnvelope, TransportMode, TransportOwner,
};
use std::{
    io,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::watch,
};

#[derive(Debug, thiserror::Error)]
pub enum RemoteError {
    #[error("remote transport: {0}")]
    Io(#[from] io::Error),
    #[error("platform resource cleanup failed: {0}")]
    Cleanup(#[source] io::Error),
    #[error("remote authorization: {0}")]
    Authorization(#[from] ContractError),
    #[error("remote connection stopped")]
    Stopped,
}
#[derive(Clone)]
pub struct RuntimeClock {
    start: Instant,
}
impl Default for RuntimeClock {
    fn default() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}
impl RuntimeClock {
    pub fn deadline_ms(&self, deadline: Instant) -> io::Result<u64> {
        deadline
            .checked_duration_since(self.start)
            .and_then(|duration| duration.as_millis().try_into().ok())
            .ok_or_else(|| io::Error::other("deadline precedes the runtime clock"))
    }
    /// Preserve the original management request clock across proof and channel rebuilding.
    pub fn from_request_start(start: Instant) -> io::Result<Self> {
        if start > Instant::now() {
            return Err(io::Error::other("future request clock"));
        }
        Ok(Self { start })
    }
    pub fn monotonic_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
    pub fn sample(&self) -> io::Result<ClockSample> {
        Ok(ClockSample {
            monotonic_ms: self.monotonic_ms(),
            unix_ms: u64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(io::Error::other)?
                    .as_millis(),
            )
            .map_err(io::Error::other)?,
        })
    }
}
fn matches_transcript(local: &EndpointProofClaims, peer: &EndpointProofClaims) -> io::Result<()> {
    let mut expected = local.clone();
    expected.challenge = peer.challenge.clone();
    if expected != *peer || peer.challenge.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "peer proof is for another permit, path or generation",
        ));
    }
    Ok(())
}
async fn read_proof<R: AsyncRead + Unpin>(read: &mut R) -> Result<NativeProof, RemoteError> {
    let frame = read_frame(read).await?;
    if frame.channel != Channel::Control {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "business data before endpoint proof",
        )
        .into());
    }
    Ok(decode_bounded(&frame.payload, CONTROL_BYTES)?)
}
async fn send_proof<W: AsyncWrite + Unpin>(
    write: &mut W,
    proof: NativeProof,
) -> Result<(), RemoteError> {
    write_frame(write, Channel::Control, &proof.encode_to_vec()).await?;
    Ok(())
}
pub async fn host_proof<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    read: &mut R,
    write: &mut W,
    session: &mut Session,
    identity: &InstallationIdentity,
    controller_key: &[u8; 32],
    clock: &RuntimeClock,
) -> Result<(), RemoteError> {
    let result = tokio::time::timeout(Duration::from_secs(3), async {
        let local = session.proof_transcript();
        let opening = read_proof(read).await?;
        let peer = opening
            .transcript
            .ok_or_else(|| io::Error::other("missing controller transcript"))?;
        matches_transcript(&local, &peer)?;
        verify_endpoint_proof(&peer, controller_key, &opening.signature)?;
        let signature = identity.prove(&local)?;
        session.confirm_endpoint(
            EndpointRole::Host,
            &identity.public_key(),
            &signature,
            clock.monotonic_ms(),
        )?;
        send_proof(
            write,
            NativeProof {
                transcript: Some(local.clone()),
                signature,
                peer_transcript_signature: identity.prove(&peer)?,
            },
        )
        .await?;
        let response = read_proof(read).await?;
        if response.transcript.as_ref() != Some(&local) {
            return Err(io::Error::other("controller answered another challenge").into());
        }
        session.confirm_endpoint(
            EndpointRole::Controller,
            controller_key,
            &response.signature,
            clock.monotonic_ms(),
        )?;
        write_frame(write, Channel::Control, b"NL-PROOF-OK").await?;
        Ok::<_, RemoteError>(())
    })
    .await;
    finish_proof(result, session)
}
pub async fn controller_proof<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    read: &mut R,
    write: &mut W,
    session: &mut Session,
    identity: &InstallationIdentity,
    host_key: &[u8; 32],
    clock: &RuntimeClock,
) -> Result<(), RemoteError> {
    let result = tokio::time::timeout(Duration::from_secs(3), async {
        let local = session.proof_transcript();
        let signature = identity.prove(&local)?;
        session.confirm_endpoint(
            EndpointRole::Controller,
            &identity.public_key(),
            &signature,
            clock.monotonic_ms(),
        )?;
        send_proof(
            write,
            NativeProof {
                transcript: Some(local.clone()),
                signature,
                peer_transcript_signature: vec![],
            },
        )
        .await?;
        let hello = read_proof(read).await?;
        let peer = hello
            .transcript
            .ok_or_else(|| io::Error::other("missing host transcript"))?;
        matches_transcript(&local, &peer)?;
        verify_endpoint_proof(&peer, host_key, &hello.signature)?;
        session.confirm_endpoint(
            EndpointRole::Host,
            host_key,
            &hello.peer_transcript_signature,
            clock.monotonic_ms(),
        )?;
        send_proof(
            write,
            NativeProof {
                transcript: Some(peer.clone()),
                signature: identity.prove(&peer)?,
                peer_transcript_signature: vec![],
            },
        )
        .await?;
        let ack = read_frame(read).await?;
        if ack.channel != Channel::Control || ack.payload != b"NL-PROOF-OK" {
            return Err(io::Error::other("host proof completion missing").into());
        }
        Ok::<_, RemoteError>(())
    })
    .await;
    finish_proof(result, session)
}
fn finish_proof(
    result: Result<Result<(), RemoteError>, tokio::time::error::Elapsed>,
    session: &mut Session,
) -> Result<(), RemoteError> {
    let result = result.unwrap_or_else(|_| {
        Err(io::Error::new(io::ErrorKind::TimedOut, "endpoint proof budget exhausted").into())
    });
    if result.is_err() {
        session.stop(StopReason::Revoked);
    }
    result
}

/// Owns the raw transport, so business callers cannot skip authorization checks.
pub struct AuthorizedConnection<R, W> {
    renewal: Option<(native_renewal::NativeRenewalPort, native_renewal::ControlIo)>,
    read: R,
    write: W,
    lease: LeaseControl,
}
/// A session created from the current approved permit. Transport setup still
/// performs both endpoint proofs; callers cannot create business queues first.
pub struct SessionSetup {
    pub session: Session,
    pub path: Path,
    pub role: EndpointRole,
    pub clock: RuntimeClock,
    pub lifecycle: SessionLifecycle,
}
impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AuthorizedConnection<R, W> {
    pub fn new(
        read: R,
        write: W,
        session: Session,
        path: Path,
        clock: RuntimeClock,
        stop: watch::Receiver<Option<StopReason>>,
    ) -> Result<Self, RemoteError> {
        Self::with_lifecycle(
            read,
            write,
            session,
            path,
            clock,
            SessionLifecycle::new(stop),
        )
    }
    pub fn with_lifecycle(
        read: R,
        write: W,
        session: Session,
        path: Path,
        clock: RuntimeClock,
        lifecycle: SessionLifecycle,
    ) -> Result<Self, RemoteError> {
        let lease = LeaseControl::new(session, path, clock, lifecycle)?;
        Ok(Self {
            read,
            write,
            lease,
            renewal: None,
        })
    }
    /// Optional only for signed media sessions; legacy sessions retain their
    /// original wire protocol. This is called only after mutual proof completes.
    pub async fn negotiate_native_renewal(mut self) -> Result<Self, RemoteError> {
        if self.lease.native_renewal_required()? {
            if let Err(error) =
                native_renewal::negotiate(&mut self.read, &mut self.write, &self.lease).await
            {
                self.lease.stop(nestlink_session::StopReason::Revoked)?;
                return Err(error);
            }
            self.renewal = Some(native_renewal::pair(&self.lease));
        }
        Ok(self)
    }
    pub fn lease_control(&self) -> LeaseControl {
        self.lease.clone()
    }
    pub fn stop(&mut self, reason: StopReason) -> Result<StopEffects, RemoteError> {
        self.lease.stop(reason)
    }
    pub fn renew(
        &mut self,
        permit: VerifiedPermit,
        request_started_ms: u64,
    ) -> Result<(), RemoteError> {
        self.lease.renew(permit, request_started_ms)
    }
    fn check_stop(&self) -> Result<(), RemoteError> {
        self.lease.remaining()?;
        Ok(())
    }
    pub async fn send(&mut self, channel: Channel, payload: &[u8]) -> Result<(), RemoteError> {
        self.check_stop()?;
        self.lease.authorize(channel)?;
        self.lease.charge_business(channel, payload.len())?;
        let outcome = lease_io(write_frame(&mut self.write, channel, payload), &self.lease).await;
        if outcome.is_err() {
            self.lease.stop(StopReason::Revoked)?;
            let _ = tokio::time::timeout(Duration::from_millis(100), self.write.shutdown()).await;
        }
        outcome
    }
    pub async fn receive(&mut self) -> Result<Frame, RemoteError> {
        self.check_stop()?;
        let outcome = lease_io(read_frame(&mut self.read), &self.lease).await;
        let frame = match outcome {
            Ok(frame) => frame,
            Err(error) => {
                self.lease.stop(StopReason::Revoked)?;
                return Err(error);
            }
        };
        self.check_stop()?;
        let authorization = self
            .lease
            .charge_business(frame.channel, frame.payload.len());
        if let Err(error) = authorization {
            self.lease.stop(StopReason::Revoked)?;
            return Err(error);
        }
        Ok(frame)
    }
}

async fn lease_io<F, T>(future: F, lease: &LeaseControl) -> Result<T, RemoteError>
where
    F: std::future::Future<Output = io::Result<T>>,
{
    let mut updates = lease.subscribe_updates();
    // Preserve partially read/written frames across renewal notifications.
    tokio::pin!(future);
    loop {
        let remaining = lease.remaining()?;
        tokio::select! {
            biased;
            change=updates.changed()=>{change.map_err(|_|RemoteError::Stopped)?;},
            _=tokio::time::sleep(remaining)=>{lease.remaining()?;},
            result=&mut future=>{lease.remaining()?;return result.map_err(RemoteError::from);},
        }
    }
}
fn permission(channel: Channel) -> Result<Permission, RemoteError> {
    Ok(match channel {
        Channel::Video | Channel::VideoFeedback => Permission::View,
        Channel::Input => Permission::Input,
        Channel::Audio => Permission::Audio,
        Channel::FileRead => Permission::FileRead,
        Channel::FileWrite => Permission::FileWrite,
        Channel::ClipboardRead => Permission::ClipboardRead,
        Channel::ClipboardWrite => Permission::ClipboardWrite,
        Channel::Control => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "control is reserved for the authenticated session handler",
            )
            .into());
        }
    })
}
