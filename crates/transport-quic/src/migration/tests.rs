use super::*;
use nestlink_protocol::network::PeerPair;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
const ALPN: &[u8] = b"nestlink/path-recovery-control-test/1";

struct Pair {
    first_identity: InstallationIdentity,
    second_identity: InstallationIdentity,
    first_endpoint: quinn::Endpoint,
    second_endpoint: quinn::Endpoint,
    first_released: tokio::sync::oneshot::Receiver<()>,
    second_released: tokio::sync::oneshot::Receiver<()>,
    first: quinn::Connection,
    second: quinn::Connection,
    binding: Binding,
}
impl Pair {
    async fn new() -> crate::Result<Self> {
        let mut first_identity = InstallationIdentity::generate();
        let mut second_identity = InstallationIdentity::generate();
        if first_identity.fingerprint() > second_identity.fingerprint() {
            std::mem::swap(&mut first_identity, &mut second_identity);
        }
        let mut server_tls = crate::tls::server_config(&second_identity, first_identity.fingerprint())?;
        server_tls.alpn_protocols = vec![ALPN.to_vec()];
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_tls)?));
        server.transport_config(crate::transport());
        let (second_endpoint, second_released) = crate::service::socket::client("127.0.0.1:0".parse()?)?;
        second_endpoint.set_server_config(Some(server));
        let mut client_tls = crate::tls::client_config(&first_identity, second_identity.fingerprint())?;
        client_tls.alpn_protocols = vec![ALPN.to_vec()];
        let mut client = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_tls)?));
        client.transport_config(crate::transport());
        let (mut first_endpoint, first_released) = crate::service::socket::client("127.0.0.1:0".parse()?)?;
        first_endpoint.set_default_client_config(client);
        let address = second_endpoint.local_addr()?;
        let (first, second) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(crate::connect(&first_endpoint, address, Duration::from_secs(5)), async {
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(second_endpoint.accept().await
                    .ok_or_else(|| io::Error::from(io::ErrorKind::ConnectionAborted))?.await?)
            })
        }).await?;
        let first = first?;
        let second = second?;
        let binding = Binding {
            deployment: [1; 32], space: [2; 32], session: [3; 32], permit: [4; 32],
            path_grant: [5; 32], transport_group: [6; 32],
            peers: PeerPair::new(PeerId(first_identity.fingerprint()), PeerId(second_identity.fingerprint()))?,
            original_route: [7; 32], candidate_route: [8; 32],
            original_connection: [9; 32], control_connection: connection_binding(&first)?,
            business_generation: 10, previous_path_epoch: 11, next_path_epoch: 12,
            expires_at_unix_ms: now_ms()? + 30_000,
        };
        assert_eq!(binding.control_connection, connection_binding(&second)?);
        Ok(Self { first_identity, second_identity, first_endpoint, second_endpoint,
            first_released, second_released, first, second, binding })
    }
    async fn close(self) -> crate::Result<()> {
        let addresses = [self.first_endpoint.local_addr()?, self.second_endpoint.local_addr()?];
        self.first_endpoint.close(0u32.into(), b"test complete");
        self.second_endpoint.close(0u32.into(), b"test complete");
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(self.first_endpoint.wait_idle(), self.second_endpoint.wait_idle())
        }).await?;
        let Self { first_endpoint, second_endpoint, first, second, first_released, second_released, .. } = self;
        drop((first, second, first_endpoint, second_endpoint));
        tokio::time::timeout(Duration::from_secs(5), async {
            first_released.await?; second_released.await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        }).await??;
        for address in addresses { drop(std::net::UdpSocket::bind(address)?); }
        Ok(())
    }
}

#[tokio::test]
async fn concurrent_owners_prove_control_on_new_pinned_connection_without_old_path_io() -> crate::Result<()> {
    let pair = Pair::new().await?;
    let (_cancel, cancel) = watch::channel(false);
    let deadline = Instant::now() + Duration::from_secs(2);
    let first_key = pair.first_identity.public_key();
    let second_key = pair.second_identity.public_key();
    let (first, second) = tokio::join!(
        exchange(&pair.first, ALPN, pair.binding.clone(), &pair.first_identity,
            &second_key, cancel.clone(), deadline, || Ok(())),
        exchange(&pair.second, ALPN, pair.binding.clone(), &pair.second_identity,
            &first_key, cancel, deadline, || Ok(()))
    );
    let first = first?; let second = second?;
    assert_eq!(first.binding(), second.binding());
    assert_eq!(first.transcript().proposal, second.transcript().proposal);
    assert_eq!(first.transcript().challenge, second.transcript().challenge);
    assert_eq!(first.binding().business_generation, 10);
    assert_eq!(first.binding().next_path_epoch, 12);
    assert!(pair.first.close_reason().is_none());
    // The helper has no reference to the old physical connection and cannot
    // open a business runtime. Its control stream succeeded independently.
    pair.close().await
}

#[tokio::test]
async fn another_scope_exporter_peer_or_alpn_never_yields_a_commit_receipt() -> crate::Result<()> {
    for mode in 0..5 {
        let pair = Pair::new().await?;
        let mut wrong = pair.binding.clone();
        match mode {
            0 => wrong.original_connection[0] ^= 1,
            1 => wrong.control_connection[0] ^= 1,
            2 => wrong.original_route[0] ^= 1,
            3 => wrong.business_generation += 1,
            _ => {},
        }
        let (_cancel, cancel) = watch::channel(false);
        let deadline = Instant::now() + Duration::from_secs(2);
        let alpn = if mode == 4 { b"wrong/1".as_slice() } else { ALPN };
        let first_key = pair.first_identity.public_key();
        let second_key = pair.second_identity.public_key();
        let (first, second) = tokio::join!(
            exchange(&pair.first, alpn, pair.binding.clone(), &pair.first_identity,
                &second_key, cancel.clone(), deadline, || Ok(())),
            exchange(&pair.second, ALPN, wrong, &pair.second_identity,
                &first_key, cancel, deadline, || Ok(()))
        );
        assert!(first.is_err() && second.is_err(), "mutation {mode}");
        assert!(pair.first.close_reason().is_some());
        pair.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn cancellation_and_revocation_before_commit_close_candidate_and_release_its_socket() -> crate::Result<()> {
    for mode in 0..2 {
        let pair = Pair::new().await?;
        let (cancel_source, cancel) = watch::channel(false);
        if mode == 0 { cancel_source.send_replace(true); }
        let current = Arc::new(AtomicBool::new(true));
        let changed = current.clone();
        let mut checks = 0;
        let check = move || {
            checks += 1;
            // Stop after capability negotiation, before the signed proposal.
            if checks >= 2 { changed.store(false, Ordering::SeqCst); }
            if changed.load(Ordering::SeqCst) { Ok(()) }
            else { Err(io::ErrorKind::PermissionDenied.into()) }
        };
        let deadline = Instant::now() + Duration::from_secs(2);
        let first_key = pair.first_identity.public_key();
        let second_key = pair.second_identity.public_key();
        let (first, second) = tokio::join!(
            exchange(&pair.first, ALPN, pair.binding.clone(), &pair.first_identity,
                &second_key, cancel.clone(), deadline, check),
            exchange(&pair.second, ALPN, pair.binding.clone(), &pair.second_identity,
                &first_key, cancel, deadline, || Ok(()))
        );
        assert!(first.is_err() && second.is_err());
        pair.close().await?;
    }
    Ok(())
}
