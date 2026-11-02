use super::*;
use nestlink_identity::InstallationIdentity;
use nestlink_protocol::network::{CORE_CAPABILITY, MIGRATION_CAPABILITY, SCHEMA_VERSION};
use std::{sync::Arc, time::Duration};

const ALPN: &[u8] = b"nestlink/network-capability-test/2";

struct Pair {
    first_endpoint: quinn::Endpoint,
    second_endpoint: quinn::Endpoint,
    first: quinn::Connection,
    second: quinn::Connection,
    first_binding: CapabilityBinding,
    second_binding: CapabilityBinding,
}
impl Pair {
    async fn new() -> crate::Result<Self> {
        let first_identity = InstallationIdentity::generate();
        let second_identity = InstallationIdentity::generate();
        let mut server_tls =
            crate::tls::server_config(&second_identity, first_identity.fingerprint())?;
        server_tls.alpn_protocols = vec![ALPN.to_vec()];
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_tls)?,
        ));
        server.transport_config(crate::transport());
        let second_endpoint = quinn::Endpoint::server(server, "127.0.0.1:0".parse()?)?;
        let mut client_tls =
            crate::tls::client_config(&first_identity, second_identity.fingerprint())?;
        client_tls.alpn_protocols = vec![ALPN.to_vec()];
        let mut client = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_tls)?,
        ));
        client.transport_config(crate::transport());
        let mut first_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
        first_endpoint.set_default_client_config(client);
        let destination = second_endpoint.local_addr()?;
        let deadline = Instant::now() + Duration::from_secs(5);
        let accept = async {
            let incoming = second_endpoint
                .accept()
                .await
                .ok_or_else(|| io::Error::from(io::ErrorKind::ConnectionAborted))?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(incoming.await?)
        };
        let (first, second) = tokio::time::timeout_at(deadline, async {
            tokio::join!(
                crate::connect(&first_endpoint, destination, Duration::from_secs(5)),
                accept
            )
        })
        .await?;
        Ok(Self {
            first_endpoint,
            second_endpoint,
            first: first?,
            second: second?,
            first_binding: CapabilityBinding {
                expected_peer: PeerId(second_identity.fingerprint()),
                business_digest: [7; 32],
                transport_group: [8; 32],
            },
            second_binding: CapabilityBinding {
                expected_peer: PeerId(first_identity.fingerprint()),
                business_digest: [7; 32],
                transport_group: [8; 32],
            },
        })
    }
    async fn close(self) -> crate::Result<()> {
        let addresses = [
            self.first_endpoint.local_addr()?,
            self.second_endpoint.local_addr()?,
        ];
        self.first_endpoint.close(0u32.into(), b"test complete");
        self.second_endpoint.close(0u32.into(), b"test complete");
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                self.first_endpoint.wait_idle(),
                self.second_endpoint.wait_idle()
            )
        })
        .await?;
        drop(self);
        for address in addresses {
            drop(std::net::UdpSocket::bind(address)?);
        }
        Ok(())
    }
}
fn offer(migration: bool, required_migration: bool) -> CapabilityOffer {
    let mut supported = vec![CORE_CAPABILITY.into()];
    if migration {
        supported.push(MIGRATION_CAPABILITY.into());
    }
    CapabilityOffer {
        schema_version: SCHEMA_VERSION,
        supported,
        required: vec![
            if required_migration {
                MIGRATION_CAPABILITY
            } else {
                CORE_CAPABILITY
            }
            .into(),
        ],
    }
}

#[tokio::test]
async fn pinned_offers_bind_original_business_and_select_only_common_features() -> crate::Result<()>
{
    let pair = Pair::new().await?;
    let first_offer = offer(true, false);
    let second_offer = offer(false, false);
    let deadline = Instant::now() + Duration::from_secs(5);
    let (first, second) = tokio::join!(
        exchange(
            &pair.first,
            true,
            ALPN,
            &pair.first_binding,
            &first_offer,
            deadline
        ),
        exchange(
            &pair.second,
            false,
            ALPN,
            &pair.second_binding,
            &second_offer,
            deadline
        )
    );
    let selected = NegotiatedProtocol::NetworkV1 {
        path_migration: false,
    };
    assert_eq!(first?, selected);
    assert_eq!(second?, selected);
    pair.first
        .send_datagram(b"authenticated business".to_vec().into())?;
    assert_eq!(
        tokio::time::timeout_at(deadline, pair.second.read_datagram())
            .await??
            .as_ref(),
        b"authenticated business"
    );
    pair.close().await
}

#[tokio::test]
async fn required_unavailable_future_or_unknown_schema_closes_without_downgrade()
-> crate::Result<()> {
    let mut future = offer(false, false);
    future.supported.push("unavailable-future-v1".into());
    future.required.push("unavailable-future-v1".into());
    let mut unknown_schema = offer(false, false);
    unknown_schema.schema_version += 1;
    for first_offer in [offer(true, true), future, unknown_schema] {
        let pair = Pair::new().await?;
        let second_offer = offer(false, false);
        let deadline = Instant::now() + Duration::from_secs(5);
        let (first, second) = tokio::join!(
            exchange(
                &pair.first,
                true,
                ALPN,
                &pair.first_binding,
                &first_offer,
                deadline
            ),
            exchange(
                &pair.second,
                false,
                ALPN,
                &pair.second_binding,
                &second_offer,
                deadline
            )
        );
        assert!(first.is_err() && second.is_err());
        assert!(pair.first.close_reason().is_some());
        pair.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn another_original_group_or_peer_or_alpn_cannot_supply_capabilities() -> crate::Result<()> {
    for mutation in 0..4 {
        let mut pair = Pair::new().await?;
        if mutation == 0 {
            pair.second_binding.transport_group = [9; 32];
        }
        if mutation == 1 {
            pair.second_binding.business_digest = [9; 32];
        }
        if mutation == 2 {
            pair.first_binding.expected_peer = PeerId([9; 32]);
        }
        let first_alpn = if mutation == 3 {
            b"wrong/2".as_slice()
        } else {
            ALPN
        };
        let first_offer = offer(false, false);
        let second_offer = offer(false, false);
        let deadline = Instant::now() + Duration::from_secs(5);
        let (first, second) = tokio::join!(
            exchange(
                &pair.first,
                true,
                first_alpn,
                &pair.first_binding,
                &first_offer,
                deadline
            ),
            exchange(
                &pair.second,
                false,
                ALPN,
                &pair.second_binding,
                &second_offer,
                deadline
            )
        );
        assert!(first.is_err() && second.is_err());
        pair.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn oversized_malformed_and_unknown_field_authenticated_offers_are_bounded()
-> crate::Result<()> {
    let envelope = Envelope {
        business_digest: [7; 32],
        transport_group: [8; 32],
        offer: offer(false, false),
    };
    let mut unknown = serde_json::to_value(&envelope)?;
    unknown["extra"] = true.into();
    for response in [
        vec![b'x'; MAX_BYTES + 1],
        b"invalid-json".to_vec(),
        serde_json::to_vec(&unknown)?,
    ] {
        let pair = Pair::new().await?;
        let local = offer(false, false);
        let deadline = Instant::now() + Duration::from_secs(5);
        let remote = async {
            let (mut send, mut receive) = pair.second.accept_bi().await?;
            let _ = receive.read_to_end(MAX_BYTES).await?;
            send.write_all(&response).await?;
            send.finish()?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let (result, _) = tokio::time::timeout_at(deadline, async {
            tokio::join!(
                exchange(
                    &pair.first,
                    true,
                    ALPN,
                    &pair.first_binding,
                    &local,
                    deadline
                ),
                remote
            )
        })
        .await?;
        assert!(result.is_err());
        tokio::time::timeout_at(deadline, pair.second.closed()).await?;
        pair.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn cancellation_and_deadline_close_the_original_connection() -> crate::Result<()> {
    for cancel in [false, true] {
        let pair = Pair::new().await?;
        let local = offer(false, false);
        let deadline = Instant::now() + Duration::from_millis(150);
        if cancel {
            let pending = exchange(
                &pair.first,
                true,
                ALPN,
                &pair.first_binding,
                &local,
                deadline,
            );
            tokio::pin!(pending);
            tokio::select! {
                result = &mut pending => return Err(format!("negotiation completed before cancellation: {result:?}").into()),
                _ = tokio::time::sleep(Duration::from_millis(20)) => {}
            }
        } else {
            assert!(
                exchange(
                    &pair.first,
                    true,
                    ALPN,
                    &pair.first_binding,
                    &local,
                    deadline
                )
                .await
                .is_err()
            );
        }
        tokio::time::timeout(Duration::from_secs(3), pair.second.closed()).await?;
        pair.close().await?;
    }
    Ok(())
}
