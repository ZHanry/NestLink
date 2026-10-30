//! Allocated node transport; never sends a management bearer to the data node.
use super::*;
use nestlink_identity::relay::{VerifiedRelayAllocation, node_relay_transcript};
use nestlink_protocol::{
    RelayTransport,
    api::{NodeRelayChallenge, NodeRelayHello},
};
use std::time::{SystemTime, UNIX_EPOCH};

/// Caller explicitly approves the node authority and this literal address.
/// The URL's Host/SNI and normal outer TLS certificate checks remain in force.
pub async fn connect_at(
    url: &str,
    installation: (&str, &InstallationIdentity),
    permit: &VerifiedPermit,
    allocation: &VerifiedRelayAllocation,
    address: SocketAddr,
) -> Result<tokio_rustls::TlsStream<ByteStream>, Error> {
    let (device, identity) = installation;
    let c = allocation.claims();
    let parsed = url::Url::parse(url).map_err(|_| Error::Invalid)?;
    if parsed.path() != format!("/api/v3/nodes/{}/relay/{}", c.node_id, c.allocation_id)
        || !allocation
            .matches(permit.claims())
            .map_err(|_| Error::Invalid)?
        || c.expires_at_unix_ms > permit.claims().expires_at_unix_ms
        || !c.transports.contains(&(RelayTransport::WssStream as i32))
    {
        return Err(Error::Invalid);
    }
    let (controller, expected) = peer_endpoint(device, identity, permit)?;
    let now: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Invalid)?
        .as_millis()
        .try_into()
        .map_err(|_| Error::Invalid)?;
    let remaining = c
        .expires_at_unix_ms
        .checked_sub(now)
        .filter(|n| *n > 0)
        .ok_or(Error::Invalid)?;
    if c.issued_at_unix_ms > now.saturating_add(1000) {
        return Err(Error::Invalid);
    }
    let exchange = async {
        let mut socket = open_socket(url, None, Some(address)).await?;
        let challenge: NodeRelayChallenge = text(&mut socket, Duration::from_secs(3)).await?;
        let nonce: [u8; 32] = URL_SAFE_NO_PAD
            .decode(challenge.nonce)
            .map_err(|_| Error::Invalid)?
            .try_into()
            .map_err(|_| Error::Invalid)?;
        let proof = node_relay_transcript(c, device, RelayTransport::WssStream, &nonce)
            .map_err(|_| Error::Invalid)?;
        let hello = NodeRelayHello {
            device_id: device.into(),
            public_key: URL_SAFE_NO_PAD.encode(identity.public_key()),
            allocation: URL_SAFE_NO_PAD.encode(allocation.signed_bytes()),
            signature: URL_SAFE_NO_PAD
                .encode(identity.sign_action(&proof).map_err(|_| Error::Invalid)?),
        };
        let hello = serde_json::to_string(&hello).map_err(|_| Error::Invalid)?;
        if hello.len() > 16384 {
            return Err(Error::Invalid);
        }
        tokio::time::timeout(
            Duration::from_millis(500),
            socket.send(Message::Text(hello.into())),
        )
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(Error::from)?;
        let ready: RelayReady = text(&mut socket, Duration::from_secs(6)).await?;
        if !ready.ready {
            return Err(Error::Invalid);
        }
        secure(socket, identity, controller, expected).await
    };
    tokio::time::timeout(Duration::from_millis(remaining.min(10000)), exchange)
        .await
        .map_err(|_| Error::Timeout)?
}
