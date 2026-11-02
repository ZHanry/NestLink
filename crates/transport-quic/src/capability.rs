//! Bounded capability exchange inside an already pinned mutual TLS connection.
//! The caller selects an explicit new ALPN and keeps its original business
//! authorization owner. A capability never grants a business or network right.
use nestlink_protocol::network::{CapabilityOffer, NegotiatedProtocol, PeerId, negotiate};
use serde::{Deserialize, Serialize};
use std::io;
use tokio::time::Instant;

const MAX_BYTES: usize = 8_192;
const FAILURE_CODE: u32 = 0x4e03;

pub struct CapabilityBinding {
    pub expected_peer: PeerId,
    pub business_digest: [u8; 32],
    pub transport_group: [u8; 32],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    business_digest: [u8; 32],
    transport_group: [u8; 32],
    offer: CapabilityOffer,
}

// Cancellation and every error close this original connection. The owner
// still retains its task/socket receipts and must await physical release.
struct Pending<'a>(Option<&'a quinn::Connection>);
impl Drop for Pending<'_> {
    fn drop(&mut self) {
        if let Some(connection) = self.0 {
            connection.close(FAILURE_CODE.into(), b"capability negotiation incomplete");
        }
    }
}

/// Consume one bidirectional stream before admitting any business data.
/// `expected_alpn` must be the caller's independently versioned capability
/// protocol; old ALPNs retain their original bytes and never call this method.
/// Errors cannot trigger a retry using old authorization or a weaker offer.
pub async fn exchange(
    connection: &quinn::Connection,
    initiator: bool,
    expected_alpn: &[u8],
    binding: &CapabilityBinding,
    local: &CapabilityOffer,
    deadline: Instant,
) -> crate::Result<NegotiatedProtocol> {
    let mut pending = Pending(Some(connection));
    binding.expected_peer.validate()?;
    local.validate()?;
    let alpn = connection
        .handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|data| data.protocol);
    if expected_alpn.is_empty()
        || alpn.as_deref() != Some(expected_alpn)
        || crate::routed::authenticated_peer_fingerprint(connection)? != binding.expected_peer.0
        || binding.business_digest == [0; 32]
        || binding.transport_group == [0; 32]
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "capability ALPN, peer or original authorization binding mismatch",
        )
        .into());
    }
    let bytes = serde_json::to_vec(&Envelope {
        business_digest: binding.business_digest,
        transport_group: binding.transport_group,
        offer: local.clone(),
    })?;
    if bytes.len() > MAX_BYTES {
        return Err(io::Error::from(io::ErrorKind::InvalidData).into());
    }
    let selected = tokio::time::timeout_at(deadline, async {
        let (mut send, mut receive) = if initiator {
            connection.open_bi().await?
        } else {
            connection.accept_bi().await?
        };
        send.write_all(&bytes).await?;
        send.finish()?;
        let bytes = receive.read_to_end(MAX_BYTES).await?;
        let remote: Envelope = serde_json::from_slice(&bytes)?;
        if remote.business_digest != binding.business_digest
            || remote.transport_group != binding.transport_group
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "capability offer belongs to another business or transport group",
            )
            .into());
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(negotiate(local, &remote.offer)?)
    })
    .await??;
    pending.0 = None;
    Ok(selected)
}

#[cfg(test)]
mod tests;
