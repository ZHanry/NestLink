//! Bounded signed control over a separately pinned candidate connection.
//! This module never exposes business streams or changes a route. The original
//! product owner decides between a proved socket switch and safe recovery.
use nestlink_identity::{InstallationIdentity, digest, network_migration::Transcript};
use nestlink_protocol::{
    network::{
        CORE_CAPABILITY, CapabilityOffer, MIGRATION_CAPABILITY, NegotiatedProtocol, PeerId,
        SCHEMA_VERSION,
    },
    network_migration::{
        Binding, CONNECTION_BINDING_LABEL, Envelope, MAX_BYTES, MAX_CONTROL_LIFETIME_MS,
    },
};
use std::{
    io,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::watch, time::Instant};

pub struct CommittedMigration(nestlink_identity::network_migration::Committed);
impl CommittedMigration {
    pub fn binding(&self) -> &Binding {
        &self.0.binding
    }
    pub fn transcript(&self) -> &nestlink_identity::network_migration::Committed {
        &self.0
    }
}

pub fn connection_binding(connection: &quinn::Connection) -> io::Result<[u8; 32]> {
    let mut material = [0; 32];
    connection
        .export_keying_material(&mut material, CONNECTION_BINDING_LABEL, b"")
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "migration TLS binding unavailable",
            )
        })?;
    let binding = digest(&material);
    material.fill(0);
    Ok(binding)
}

fn now_ms() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_millis()
        .try_into()
        .map_err(io::Error::other)
}

struct Pending<'a>(Option<&'a quinn::Connection>);
impl Drop for Pending<'_> {
    fn drop(&mut self) {
        if let Some(connection) = self.0 {
            connection.close(0x4e04u32.into(), b"migration control incomplete");
        }
    }
}
fn cancelled(cancel: &watch::Receiver<bool>) -> bool {
    *cancel.borrow() || cancel.has_changed().is_err()
}
async fn wait_cancel(cancel: &mut watch::Receiver<bool>) {
    loop {
        if cancelled(cancel) {
            return;
        }
        if cancel.changed().await.is_err() {
            return;
        }
    }
}
async fn read(receive: &mut quinn::RecvStream) -> crate::Result<Envelope> {
    let mut bytes = [0; MAX_BYTES];
    receive.read_exact(&mut bytes).await?;
    Ok(Envelope::decode(&bytes)?)
}
async fn write(send: &mut quinn::SendStream, envelope: &Envelope) -> crate::Result<()> {
    send.write_all(&envelope.encode()?).await?;
    Ok(())
}
async fn end(receive: &mut quinn::RecvStream) -> crate::Result<()> {
    let mut extra = [0; 1];
    if receive.read(&mut extra).await?.is_some() {
        return Err(io::Error::from(io::ErrorKind::InvalidData).into());
    }
    Ok(())
}

/// Both endpoints explicitly call this only on a control-only standby. The
/// ordered installation peer pair elects the writer even when both owners
/// trigger concurrently. QUIC retransmits lost control packets; the signed
/// transcript also makes duplicate application phases idempotent.
///
/// `expected` comes from the exact original verified owner. Its expiry is the
/// original authority bound; the leader chooses a control lifetime <= 2 s.
/// `check_current` must synchronously recheck the retained original authority,
/// local cancellation and business terminal state. The caller retains every
/// endpoint/task release receipt; cancelling this future closes only standby.
#[allow(clippy::too_many_arguments)]
pub async fn exchange<F>(
    connection: &quinn::Connection,
    expected_alpn: &[u8],
    expected: Binding,
    local: &InstallationIdentity,
    remote_key: &[u8; 32],
    mut cancel: watch::Receiver<bool>,
    deadline: Instant,
    mut check_current: F,
) -> crate::Result<CommittedMigration>
where
    F: FnMut() -> io::Result<()> + Send,
{
    let mut pending = Pending(Some(connection));
    check_current()?;
    let now = now_ms()?;
    let expires = expected.expires_at_unix_ms;
    let remaining = expires
        .checked_sub(now)
        .filter(|value| *value > 0)
        .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?;
    let deadline = deadline
        .min(Instant::now() + Duration::from_millis(remaining.min(MAX_CONTROL_LIFETIME_MS)));
    let local_peer = PeerId(local.fingerprint());
    if cancelled(&cancel)
        || Instant::now() >= deadline
        || expected.control_connection != connection_binding(connection)?
        || expected.original_connection == expected.control_connection
        || crate::routed::authenticated_peer_fingerprint(connection)? != digest(remote_key)
    {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied).into());
    }
    let mut transcript = Transcript::new(expected.clone(), local_peer, *remote_key, expires, now)?;
    let leader = transcript.leader();
    let operation = async {
        let selected = crate::capability::exchange(
            connection,
            leader,
            expected_alpn,
            &crate::capability::CapabilityBinding {
                expected_peer: PeerId(digest(remote_key)),
                business_digest: expected.permit,
                transport_group: expected.transport_group,
            },
            &CapabilityOffer {
                schema_version: SCHEMA_VERSION,
                supported: vec![CORE_CAPABILITY.into(), MIGRATION_CAPABILITY.into()],
                required: vec![CORE_CAPABILITY.into(), MIGRATION_CAPABILITY.into()],
            },
            deadline,
        )
        .await?;
        if selected
            != (NegotiatedProtocol::NetworkV1 {
                path_migration: true,
            })
        {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied).into());
        }
        check_current()?;
        let (mut send, mut receive) = if leader {
            connection.open_bi().await?
        } else {
            connection.accept_bi().await?
        };
        if leader {
            write(&mut send, &transcript.propose(local, now_ms()?, true)?).await?;
            let accepted = read(&mut receive).await?;
            check_current()?;
            let commit = transcript
                .receive(local, &accepted, now_ms()?, true)?
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
            write(&mut send, &commit).await?;
            send.finish()?;
            let committed = read(&mut receive).await?;
            check_current()?;
            if transcript
                .receive(local, &committed, now_ms()?, true)?
                .is_some()
            {
                return Err(io::Error::from(io::ErrorKind::InvalidData).into());
            }
            end(&mut receive).await?;
        } else {
            let proposal = read(&mut receive).await?;
            check_current()?;
            let accepted = transcript
                .receive(local, &proposal, now_ms()?, true)?
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
            write(&mut send, &accepted).await?;
            let commit = read(&mut receive).await?;
            check_current()?;
            let committed = transcript
                .receive(local, &commit, now_ms()?, true)?
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
            end(&mut receive).await?;
            check_current()?;
            write(&mut send, &committed).await?;
            send.finish()?;
            // Retain the connection until Quinn confirms the final phase was
            // received; no immediate close can discard its reliable bytes.
            if send.stopped().await?.is_some() {
                return Err(io::Error::from(io::ErrorKind::ConnectionAborted).into());
            }
        }
        check_current()?;
        if Instant::now() >= deadline {
            return Err(io::Error::from(io::ErrorKind::TimedOut).into());
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(CommittedMigration(
            transcript
                .receipt()
                .cloned()
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?,
        ))
    };
    let receipt = tokio::select! { biased;
        _ = wait_cancel(&mut cancel) => return Err(io::Error::from(io::ErrorKind::Interrupted).into()),
        result = tokio::time::timeout_at(deadline, operation) => result??,
    };
    if cancelled(&cancel) || Instant::now() >= deadline {
        return Err(io::Error::from(io::ErrorKind::Interrupted).into());
    }
    pending.0 = None;
    Ok(receipt)
}

#[cfg(test)]
mod tests;
