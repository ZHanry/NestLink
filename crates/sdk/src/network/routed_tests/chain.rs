//! Actual NRD2 transport plus the production business and OS file-read owners.
use super::super::{RemoteChainAuthority, authorize_remote_chain};
use super::*;
use nestlink_platform_files::{ApprovedReadRoot, FileRoots};
use nestlink_remote::files::{FileReadClient, FileReadServer, FileReadVerifier};

struct ChainFixture {
    base: Fixture,
    second_relay: InstallationIdentity,
    path: VerifiedNetworkPath,
    transits: [VerifiedNetworkGrant; 2],
}
impl ChainFixture {
    fn new(controller_first: bool) -> Result<Self> {
        let base = Fixture::with_peer_order(true, 12_000, controller_first)?;
        let second_relay = InstallationIdentity::generate();
        let signer = NetworkAuthoritySigner::from_master_seed(&[83; 32])?;
        let context = base.context();
        let signed =
            |view: &nestlink_protocol::api::NetworkGrantView| -> Result<VerifiedNetworkGrant> {
                Ok(verify_network_grant(
                    &nestlink_identity::network::SignedNetworkGrant {
                        claims: URL_SAFE_NO_PAD.decode(&view.claims)?,
                        signature: URL_SAFE_NO_PAD.decode(&view.signature)?,
                    },
                    &context,
                )?)
            };
        let mut members = Vec::new();
        for (view, device) in [
            (&base.response.path.controller_membership, &base.controller),
            (&base.response.path.host_membership, &base.host),
        ] {
            members.push(VerifiedMembership::from_grant(
                signed(view)?,
                &context,
                &device.device_id,
                &device.identity.public_key(),
                1,
            )?);
        }
        let relays = [
            PeerId(base.relay.fingerprint()),
            PeerId(second_relay.fingerprint()),
        ];
        let mut claims = base.path.claims().clone();
        claims.policy.relays = relays.to_vec();
        claims.policy.relays.sort();
        claims.policy.max_hops = 2;
        let path = VerifiedNetworkPath::from_grants(
            &context,
            [members.remove(0), members.remove(0)],
            base.connectivity.clone(),
            verify_network_grant(&signer.sign(&GrantClaims::Path(claims))?, &context)?,
            base.permit.digest(),
        )?;
        let GrantClaims::Transit(mut first) = base.transit.claims().clone() else {
            return Err("transit".into());
        };
        first.transport_group = path.transport_group_id();
        first.next = relays[1];
        first.remaining_hops = 2;
        let mut second = first.clone();
        second.scope.grant_id = random_id();
        second.relay = relays[1];
        second.previous = relays[0];
        second.next = path.peers().second;
        second.remaining_hops = 1;
        let transits = [
            verify_network_grant(&signer.sign(&GrantClaims::Transit(first))?, &context)?,
            verify_network_grant(&signer.sign(&GrantClaims::Transit(second))?, &context)?,
        ];
        Ok(Self {
            base,
            second_relay,
            path,
            transits,
        })
    }
    fn authority<'a>(&'a self, context: &'a NetworkVerification<'a>) -> RemoteChainAuthority<'a> {
        RemoteChainAuthority {
            context,
            path: &self.path,
            connectivity: &self.base.connectivity,
            transits: &self.transits,
        }
    }
    fn authorization(&self) -> Result<(RouteAuthorization, RouteRevocation)> {
        Ok(RouteAuthorization::remote_chain(
            &self.base.context(),
            &self.path,
            &self.base.connectivity,
            &self.transits,
            &self.base.permit,
        )?)
    }
}

async fn neighbors_v2(
    local: &InstallationIdentity,
    remote: &InstallationIdentity,
    deadline: Instant,
) -> Result<(Adjacency, Adjacency, [SocketAddr; 2])> {
    let listener =
        AdjacencyEndpoint::bind_chain("127.0.0.1:0".parse()?, local, PeerId(remote.fingerprint()))?;
    let connector =
        AdjacencyEndpoint::bind_chain("127.0.0.1:0".parse()?, remote, PeerId(local.fingerprint()))?;
    let addresses = [listener.local_addr()?, connector.local_addr()?];
    let (a, b) = tokio::try_join!(
        listener.accept(deadline),
        connector.connect(addresses[0], deadline)
    )?;
    Ok((a, b, addresses))
}
fn forwarding(mut relay: RelayForwarder) -> Abort<io::Result<(u64, u64)>> {
    Abort(tokio::spawn(async move {
        let stopped = relay.run().await;
        let result = (relay.forwarded_fragments(), relay.charged_bytes());
        relay
            .close_and_wait(Instant::now() + Duration::from_secs(5))
            .await?;
        assert!(stopped.is_err());
        Ok(result)
    }))
}
struct SourceDirectory(std::path::PathBuf);
impl SourceDirectory {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!("nestlink-nrd2-file-{}", random_id()));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for SourceDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.0.join("source"));
        let _ = std::fs::remove_dir(&self.0);
    }
}

#[tokio::test]
async fn sdk_four_node_chain_reads_an_approved_os_file_after_both_business_proofs() -> Result {
    transfer(true).await
}
#[tokio::test]
async fn sdk_four_node_chain_preserves_host_initiated_quic_and_controller_file_permissions()
-> Result {
    transfer(false).await
}
async fn transfer(controller_first: bool) -> Result {
    let f = ChainFixture::new(controller_first)?;
    let context = f.base.context();
    let deadline = Instant::now() + Duration::from_secs(5);
    let (canonical_first, canonical_second) = if controller_first {
        (&f.base.controller, &f.base.host)
    } else {
        (&f.base.host, &f.base.controller)
    };
    let (left_in, first, a) =
        neighbors_v2(&f.base.relay, &canonical_first.identity, deadline).await?;
    let (left_out, right_in, b) = neighbors_v2(&f.base.relay, &f.second_relay, deadline).await?;
    let (right_out, second, c) =
        neighbors_v2(&f.second_relay, &canonical_second.identity, deadline).await?;
    let (left_auth, left_stop) = f.authorization()?;
    let (right_auth, right_stop) = f.authorization()?;
    let mut left = forwarding(RelayForwarder::new(left_auth, left_in, left_out)?);
    let mut right = forwarding(RelayForwarder::new(right_auth, right_in, right_out)?);
    let (controller, host) = if controller_first {
        (first, second)
    } else {
        (second, first)
    };
    let (_controller_signal, controller_stop) = watch::channel(None);
    let (_host_signal, host_stop) = watch::channel(None);
    let host_key = f.base.host.identity.public_key();
    let controller_key = f.base.controller.identity.public_key();
    let (controller, host) = tokio::join!(
        authorize_remote_chain(
            f.authority(&context),
            controller,
            f.base
                .setup(&f.base.permit, EndpointRole::Controller, controller_stop)?,
            &f.base.controller,
            &host_key,
            deadline
        ),
        authorize_remote_chain(
            f.authority(&context),
            host,
            f.base
                .setup(&f.base.permit, EndpointRole::Host, host_stop)?,
            &f.base.host,
            &controller_key,
            deadline
        ),
    );
    report_pair(&controller, &host);
    let (mut controller, mut host) = (controller?, host?);
    let observations = [
        original_path_observation(&controller, &f.base.permit, &f.path)?,
        original_path_observation(&host, &f.base.permit, &f.path)?,
    ];
    assert_eq!(
        controller.lease_control().current_native_permit()?.digest(),
        f.base.permit.digest()
    );
    assert_eq!(
        host.lease_control().current_native_permit()?.digest(),
        f.base.permit.digest()
    );
    assert!(
        matches!(controller.send(Channel::Input,b"unapproved").await,
        Err(RemoteError::Authorization(ref error)) if error.code==nestlink_protocol::ErrorCode::PermissionRequired)
    );
    let directory = SourceDirectory::new()?;
    let bytes: Vec<_> = (0..98_335).map(|index| (index % 251) as u8).collect();
    std::fs::write(directory.0.join("source"), &bytes)?;
    let root_id = random_id();
    let (root, _consent) =
        ApprovedReadRoot::open(&root_id, &directory.0, nestlink_protocol::FILE_SIZE_BYTES)?;
    let generation = f.base.permit.claims().connection_generation;
    let mut server = FileReadServer::start(&mut host, generation, FileRoots::new(vec![root])?)?;
    let mut client = FileReadClient::attach(&mut controller, generation)?;
    let mut download = tokio::time::timeout_at(
        deadline,
        client.open(&random_id(), &root_id, "source", 0, None),
    )
    .await??;
    assert_eq!(download.manifest().sha256, digest(&bytes));
    let mut verifier = FileReadVerifier::new(download.manifest().clone())?;
    let mut received = Vec::new();
    while let Some(chunk) = tokio::time::timeout_at(deadline, client.next(&mut download)).await?? {
        verifier.accept(&chunk)?;
        received.extend_from_slice(&chunk.data);
    }
    verifier.finish()?;
    assert!(download.source_verified());
    assert_eq!(received, bytes);
    client.retire()?;
    server.shutdown(StopReason::ExplicitExit).await?;
    controller.lease_control().stop(StopReason::ExplicitExit)?;
    host.lease_control().stop(StopReason::ExplicitExit)?;
    let cleanup = Instant::now() + Duration::from_secs(5);
    let (a_report, b_report) = tokio::time::timeout_at(cleanup, async {
        tokio::try_join!(controller.wait_stopped(), host.wait_stopped())
    })
    .await??;
    assert_eq!(a_report.reason, StopReason::ExplicitExit);
    assert_eq!(b_report.reason, StopReason::ExplicitExit);
    for observation in &observations {
        let stopped = observation.snapshot();
        assert!(stopped.stopped);
        assert_eq!(stopped.rtt, None);
        assert_eq!(stopped.binding, *observation.binding());
    }
    left_stop.revoke();
    right_stop.revoke();
    for task in [&mut left, &mut right] {
        let (fragments, charged) = tokio::time::timeout_at(cleanup, &mut task.0).await???;
        assert!(fragments > 0 && charged >= bytes.len() as u64);
    }
    for address in a.into_iter().chain(b).chain(c) {
        drop(std::net::UdpSocket::bind(address)?);
    }
    drop(observations);
    eprintln!(
        "SDK NRD2 business: verified_os_file_bytes={}, input_denied=true, released_udp_sockets=6",
        bytes.len()
    );
    Ok(())
}
