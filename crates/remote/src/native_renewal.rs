//! Native-only post-proof control and live execution fencing.
use std::io;
/// Implementations fence execution retirement throughout this synchronous call.
/// They must invoke the operation exactly once while the actual owner is live.
/// No I/O, codec work or await belongs inside the operation.
pub trait NativeExecutionFence: Send + Sync {
    fn with_current(&self, operation: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()>;
}

use crate::{LeaseControl, RemoteError, lease_io};
use nestlink_protocol::native_renewal::{HELLO, MAX_BYTES};
use nestlink_transport_stream::{Channel, read_channel_frame, write_frame};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc,
};
/// A single claimed port, constructed only following mutual endpoint proof and
/// explicit version exchange. Business queue senders cannot construct one.
pub struct NativeRenewalPort {
    lease: LeaseControl,
    incoming: mpsc::Receiver<Vec<u8>>,
    outgoing: mpsc::Sender<Vec<u8>>,
}
pub(crate) struct ControlIo {
    pub incoming: mpsc::Sender<Vec<u8>>,
    pub outgoing: mpsc::Receiver<Vec<u8>>,
}
pub(crate) fn pair(lease: &LeaseControl) -> (NativeRenewalPort, ControlIo) {
    let (in_tx, in_rx) = mpsc::channel(4);
    let (out_tx, out_rx) = mpsc::channel(4);
    (
        NativeRenewalPort {
            lease: lease.clone(),
            incoming: in_rx,
            outgoing: out_tx,
        },
        ControlIo {
            incoming: in_tx,
            outgoing: out_rx,
        },
    )
}
impl NativeRenewalPort {
    pub async fn send(&self, bytes: Vec<u8>) -> Result<(), RemoteError> {
        if bytes.len() > MAX_BYTES {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "renewal frame too large").into(),
            );
        }
        lease_io(
            async {
                self.outgoing
                    .send(bytes)
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "renewal port closed"))
            },
            &self.lease,
        )
        .await
    }
    pub async fn receive(&mut self) -> Result<Vec<u8>, RemoteError> {
        lease_io(
            async {
                self.incoming
                    .recv()
                    .await
                    .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "renewal port closed"))
            },
            &self.lease,
        )
        .await
    }
}
impl Drop for NativeRenewalPort {
    fn drop(&mut self) {
        let _ = self
            .lease
            .stop_if_running(nestlink_session::StopReason::Revoked);
    }
}
pub(crate) async fn negotiate<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    read: &mut R,
    write: &mut W,
    lease: &LeaseControl,
) -> Result<(), RemoteError> {
    let budget = lease.remaining()?.min(std::time::Duration::from_secs(1));
    tokio::time::timeout(budget, async {
        lease_io(write_frame(write, Channel::Control, HELLO), lease).await?;
        let frame = lease_io(
            read_channel_frame(read, Channel::Control, HELLO.len()),
            lease,
        )
        .await?;
        if frame.payload != HELLO {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported native renewal version",
            )
            .into());
        }
        Ok::<_, RemoteError>(())
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "renewal version negotiation expired",
        )
    })?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthorizedConnection, RuntimeClock, SessionLifecycle};
    use nestlink_auth::random_id;
    use nestlink_identity::{InstallationIdentity, PermitSigner, verify_permit};
    use nestlink_policy::PathSet;
    use nestlink_protocol::{Path, Permission, PermitClaims};
    use nestlink_session::{EndpointRole, Session, SessionBinding, StopReason};
    use prost::Message;
    use tokio::{
        io::{AsyncWriteExt, split},
        sync::watch,
    };
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
    fn active_with_permissions(
        lifetime: u64,
        permissions: Vec<Permission>,
    ) -> Result<(Session, RuntimeClock, PermitSigner, PermitClaims)> {
        let controller = InstallationIdentity::generate();
        let host = InstallationIdentity::generate();
        let clock = RuntimeClock::default();
        let now = clock.sample()?;
        let binding = SessionBinding {
            media: None,
            deployment_id: random_id(),
            security_epoch: 1,
            session_id: random_id(),
            account_id: random_id(),
            controller_device_id: random_id(),
            host_device_id: random_id(),
            controller_key_sha256: controller.fingerprint(),
            host_key_sha256: host.fingerprint(),
            resource_id: random_id(),
            policy_revision: 1,
            connection_generation: 9,
            capability_sha256: [9; 32],
            granted_permissions: permissions.clone(),
            supported_capabilities: vec!["vp8".into()],
            local_paths: PathSet::DIRECT,
        };
        let claims = PermitClaims {
            media_format_version: 0,
            media_formats: Vec::new(),
            media_format_sha256: Vec::new(),
            schema_version: 1,
            deployment_id: binding.deployment_id.clone(),
            security_epoch: 1,
            session_id: binding.session_id.clone(),
            account_id: binding.account_id.clone(),
            controller_device_id: binding.controller_device_id.clone(),
            host_device_id: binding.host_device_id.clone(),
            controller_key_sha256: controller.fingerprint().to_vec(),
            host_key_sha256: host.fingerprint().to_vec(),
            resource_id: binding.resource_id.clone(),
            permissions: permissions.iter().map(|p| *p as i32).collect(),
            paths: vec![Path::Direct as i32],
            policy_revision: 1,
            connection_generation: 9,
            lease_sequence: 1,
            issued_at_unix_ms: now.unix_ms,
            expires_at_unix_ms: now.unix_ms + lifetime,
            capability_sha256: vec![9; 32],
            required_capabilities: vec!["vp8".into()],
        };
        let signer = PermitSigner::generate();
        let mut session = Session::activate(
            verify_permit(&signer.sign(&claims)?.encode_to_vec(), &signer.public_key())?,
            binding,
            Path::Direct,
            now.monotonic_ms,
            now,
        )?;
        let transcript = session.proof_transcript();
        for (role, identity) in [
            (EndpointRole::Controller, controller),
            (EndpointRole::Host, host),
        ] {
            session.confirm_endpoint(
                role,
                &identity.public_key(),
                &identity.prove(&transcript)?,
                clock.monotonic_ms(),
            )?;
        }
        Ok((session, clock, signer, claims))
    }

    #[tokio::test]
    async fn private_control_crosses_proved_stream_but_business_control_stays_rejected() -> Result {
        let (a, clock_a, _, _) = active_with_permissions(15000, vec![Permission::View])?;
        let (b, clock_b, _, _) = active_with_permissions(15000, vec![Permission::View])?;
        let (io_a, io_b) = tokio::io::duplex(131072);
        let (read_a, write_a) = split(io_a);
        let (read_b, write_b) = split(io_b);
        let (_stop_a, stop_a) = watch::channel(None);
        let (_stop_b, stop_b) = watch::channel(None);
        let mut a = AuthorizedConnection::with_lifecycle(
            read_a,
            write_a,
            a,
            Path::Direct,
            clock_a,
            SessionLifecycle::new(stop_a),
        )?;
        let mut b = AuthorizedConnection::with_lifecycle(
            read_b,
            write_b,
            b,
            Path::Direct,
            clock_b,
            SessionLifecycle::new(stop_b),
        )?;
        tokio::try_join!(
            negotiate(&mut a.read, &mut a.write, &a.lease),
            negotiate(&mut b.read, &mut b.write, &b.lease)
        )?;
        a.renewal = Some(pair(&a.lease));
        b.renewal = Some(pair(&b.lease));
        let mut a = a.into_channels();
        let mut b = b.into_channels();
        let port_a = a.take_native_renewal_port().ok_or("missing private port")?;
        let mut port_b = b.take_native_renewal_port().ok_or("missing private port")?;
        assert!(a.take_native_renewal_port().is_none());
        assert!(
            a.sender()
                .send(Channel::Control, b"forged business control")
                .await
                .is_err()
        );
        port_a.send(b"bounded private control".to_vec()).await?;
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(1), port_b.receive()).await??,
            b"bounded private control"
        );
        assert!(port_a.send(vec![0; MAX_BYTES + 1]).await.is_err());
        a.shutdown(StopReason::ExplicitExit).await?;
        b.shutdown(StopReason::ExplicitExit).await?;
        Ok(())
    }
    #[tokio::test]
    async fn authenticated_version_exchange_rejects_unknown_version() -> Result {
        let (session, clock, _, _) = active_with_permissions(15000, vec![Permission::View])?;
        let (_stop, receiver) = watch::channel(None);
        let lease = LeaseControl::from_proved_session(
            session,
            Path::Direct,
            clock,
            SessionLifecycle::new(receiver),
        )?;
        let (io, mut peer) = tokio::io::duplex(1024);
        let (mut read, mut write) = split(io);
        let peer = tokio::spawn(async move {
            write_frame(&mut peer, Channel::Control, b"NL-RENEW\0\x02").await
        });
        assert!(negotiate(&mut read, &mut write, &lease).await.is_err());
        peer.await??;
        lease.stop(StopReason::ExplicitExit)?;
        Ok(())
    }
    #[tokio::test]
    async fn native_control_cap_is_checked_before_body_allocation() -> Result {
        let (mut write, mut read) = tokio::io::duplex(64);
        write.write_all(&[1, Channel::Control as u8]).await?;
        write.write_u32((MAX_BYTES + 1) as u32).await?;
        // No body is sent: a reader that allocates/waits before enforcing the
        // native cap would time out rather than reject this header.
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                nestlink_transport_stream::read_frame_control_bounded(&mut read, MAX_BYTES)
            )
            .await?
            .is_err()
        );
        Ok(())
    }
}
