//! Signed graph observations exercise candidate selection, not business traffic.
use nestlink_connectivity::topology::{EndpointAttachments, MAX_GRAPH_NODES, TopologyGraph};
use nestlink_identity::{
    InstallationIdentity,
    network::{
        NetworkAuthoritySigner, NetworkVerification, VerifiedMembership, VerifiedNetworkPath,
        verify_network_grant,
    },
    network_topology::{
        VerifiedTopologyAdvertisement, VerifiedTopologyUpdate, verify_topology_advertisement,
        verify_topology_publisher, verify_topology_report, verify_topology_update,
    },
    nodes::NodeIdentity,
};
use nestlink_protocol::{
    network::{
        ConnectivityClaims, GrantClaims, GrantScope, MembershipClaims, PathClaims, PathPolicy,
        PeerId, PeerPair, Purpose, SpaceRole,
    },
    network_topology::{
        BootIncarnation, SignedTopologyAdvertisement, TopologyChange, TopologyDeltaEntry,
        TopologyNeighbor, TopologyPublisherClaims, TopologyReport, TopologySync, TopologyUpdate,
        TopologyWithdrawal,
    },
};
use std::collections::BTreeSet;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const DEPLOYMENT: &str = "51fdac9e-235d-4688-8783-239f97457606";
const SPACE: &str = "f0c1429b-167b-4f87-897e-606f934e42ca";
const NONCE: [u8; 32] = [51; 32];

fn id(value: u64) -> String {
    format!("00000000-0000-4000-8000-{value:012x}")
}
fn boot(generation: u64, runtime: u64) -> BootIncarnation {
    BootIncarnation {
        runtime_generation: generation,
        runtime_id: id(runtime),
    }
}
fn scope(value: u64) -> GrantScope {
    GrantScope {
        schema_version: 1,
        deployment_id: DEPLOYMENT.into(),
        space_id: SPACE.into(),
        grant_id: id(value),
        policy_epoch: 1,
        not_before_ms: 1000,
        expires_at_ms: 20_000,
    }
}
struct Ad {
    signed: SignedTopologyAdvertisement,
    verified: VerifiedTopologyAdvertisement,
}
impl Ad {
    fn withdrawal(&self) -> TopologyChange {
        let report = &self.verified.claims().report;
        TopologyChange::Withdraw(TopologyWithdrawal {
            node_id: report.node_id.clone(),
            peer: report.peer,
            publisher_digest: report.publisher_digest,
            incarnation: report.incarnation.clone(),
            sequence: report.sequence,
        })
    }
}
struct Fixture {
    authority: NetworkAuthoritySigner,
    key: [u8; 32],
    nodes: [NodeIdentity; 3],
    peers: [PeerId; 3],
    endpoints: [InstallationIdentity; 2],
    revoked: BTreeSet<String>,
}
impl Fixture {
    fn new() -> Result<Self> {
        let authority = NetworkAuthoritySigner::from_master_seed(&[22; 32])?;
        let key = authority.public_key();
        let nodes = [
            NodeIdentity::from_seed(&[10; 32]),
            NodeIdentity::from_seed(&[11; 32]),
            NodeIdentity::from_seed(&[12; 32]),
        ];
        let peers = nodes
            .each_ref()
            .map(|node| PeerId::from_public_key(&node.public_key()));
        Ok(Self {
            authority,
            key,
            nodes,
            peers,
            endpoints: [
                InstallationIdentity::from_seed([40; 32]),
                InstallationIdentity::from_seed([41; 32]),
            ],
            revoked: BTreeSet::new(),
        })
    }
    fn context(&self, now_ms: u64) -> NetworkVerification<'_> {
        NetworkVerification {
            authority_key: &self.key,
            deployment_id: DEPLOYMENT,
            space_id: SPACE,
            policy_epoch: 1,
            now_ms,
            revoked_grant_ids: &self.revoked,
        }
    }
    fn ad(
        &self,
        node: usize,
        sequence: u64,
        neighbors: &[(usize, bool, u64, u64)],
        expires: u64,
    ) -> Result<Ad> {
        self.incarnated_ad(node, sequence, neighbors, expires, boot(1, 90))
    }
    fn incarnated_ad(
        &self,
        node: usize,
        sequence: u64,
        neighbors: &[(usize, bool, u64, u64)],
        expires: u64,
        incarnation: BootIncarnation,
    ) -> Result<Ad> {
        let mut allowed_neighbors: Vec<_> = self
            .peers
            .iter()
            .copied()
            .filter(|peer| peer != &self.peers[node])
            .collect();
        allowed_neighbors.sort();
        let node_id = id(100 + node as u64);
        let publisher = self
            .authority
            .sign_topology_publisher(&TopologyPublisherClaims {
                scope: scope(200 + node as u64),
                node_id: node_id.clone(),
                public_key: self.nodes[node].public_key(),
                peer: self.peers[node],
                incarnation: incarnation.clone(),
                allowed_neighbors,
                route_export_digests: vec![],
                allowed_prefixes: vec![],
            })?;
        let publisher = verify_topology_publisher(
            &publisher,
            &self.context(3000),
            &node_id,
            &self.nodes[node].public_key(),
            &incarnation,
            &[],
        )?;
        let mut neighbors: Vec<_> = neighbors
            .iter()
            .map(
                |(remote, up, local_revision, remote_revision)| TopologyNeighbor {
                    local: self.peers[node],
                    remote: self.peers[*remote],
                    up: *up,
                    local_endpoint_revision: *local_revision,
                    remote_endpoint_revision: *remote_revision,
                },
            )
            .collect();
        neighbors.sort_by_key(|edge| edge.remote);
        let report = self.nodes[node].sign_topology_report(&TopologyReport {
            schema_version: 1,
            deployment_id: DEPLOYMENT.into(),
            space_id: SPACE.into(),
            policy_epoch: 1,
            node_id,
            peer: self.peers[node],
            publisher_digest: publisher.digest(),
            incarnation: incarnation.clone(),
            sequence,
            not_before_ms: 2000,
            expires_at_ms: expires,
            neighbors,
            prefixes: vec![],
        })?;
        let report =
            verify_topology_report(&report, &publisher, &self.context(3000), &incarnation, 0)?;
        let signed = self
            .authority
            .sign_topology_advertisement(&report, 3000, expires)?;
        let verified = verify_topology_advertisement(
            &signed,
            &publisher,
            &self.context(3000),
            &incarnation,
            0,
        )?;
        Ok(Ad { signed, verified })
    }
    fn update(&self, now: u64, sync: TopologySync) -> Result<VerifiedTopologyUpdate> {
        let signed = self.authority.sign_topology_update(&TopologyUpdate {
            schema_version: 1,
            deployment_id: DEPLOYMENT.into(),
            space_id: SPACE.into(),
            policy_epoch: 1,
            query_nonce: NONCE,
            issued_at_ms: now,
            expires_at_ms: now + 1000,
            sync,
        })?;
        Ok(verify_topology_update(&signed, &self.context(now), &NONCE)?)
    }
    fn full(&self, now: u64, cursor: u64, ads: &[&Ad]) -> Result<VerifiedTopologyUpdate> {
        self.update(
            now,
            TopologySync::Full {
                cursor,
                advertisements: ads.iter().map(|ad| ad.signed.clone()).collect(),
            },
        )
    }
    fn delta(
        &self,
        now: u64,
        after: u64,
        changes: Vec<TopologyChange>,
    ) -> Result<VerifiedTopologyUpdate> {
        let cursor = after + changes.len() as u64;
        self.update(
            now,
            TopologySync::Delta {
                after_cursor: after,
                cursor,
                has_more: false,
                changes: changes
                    .into_iter()
                    .enumerate()
                    .map(|(offset, change)| TopologyDeltaEntry {
                        cursor: after + offset as u64 + 1,
                        change,
                    })
                    .collect(),
            },
        )
    }
    fn full_graph(&self, ads: &[&Ad]) -> Result<TopologyGraph> {
        let mut graph = TopologyGraph::new(&self.context(3000))?;
        graph.apply(
            &self.context(3000),
            &self.full(3000, 7, ads)?,
            &ads.iter().map(|ad| ad.verified.clone()).collect::<Vec<_>>(),
        )?;
        Ok(graph)
    }
    fn endpoint(&self, index: usize, relays: Vec<PeerId>) -> Result<EndpointAttachments> {
        Ok(EndpointAttachments::new(
            PeerId::from_public_key(&self.endpoints[index].public_key()),
            relays,
        )?)
    }
    fn path(&self, maximum: u8, mut relays: Vec<PeerId>) -> Result<VerifiedNetworkPath> {
        relays.sort();
        let mut members = Vec::new();
        for (index, device) in self.endpoints.iter().enumerate() {
            let installation = id(300 + index as u64);
            let signed = self
                .authority
                .sign(&GrantClaims::Membership(MembershipClaims {
                    scope: scope(400 + index as u64),
                    installation_id: installation.clone(),
                    peer: PeerId::from_public_key(&device.public_key()),
                    public_key: device.public_key(),
                    membership_epoch: 1,
                    role: SpaceRole::Member,
                }))?;
            members.push(VerifiedMembership::from_grant(
                verify_network_grant(&signed, &self.context(3000))?,
                &self.context(3000),
                &installation,
                &device.public_key(),
                1,
            )?);
        }
        members.sort_by_key(VerifiedMembership::peer);
        let members: [VerifiedMembership; 2] =
            members.try_into().map_err(|_| "fixture membership count")?;
        let peers = PeerPair::new(members[0].peer(), members[1].peer())?;
        let signed = self
            .authority
            .sign(&GrantClaims::Connectivity(ConnectivityClaims {
                scope: scope(500),
                peers,
                purpose: Purpose::RemoteControl,
                membership_digests: [members[0].digest(), members[1].digest()],
                business_grant_digest: [42; 32],
            }))?;
        let connection = verify_network_grant(&signed, &self.context(3000))?;
        let signed = self.authority.sign(&GrantClaims::Path(PathClaims {
            scope: scope(501),
            peers,
            purpose: Purpose::RemoteControl,
            connectivity_grant_digest: connection.digest(),
            policy: PathPolicy {
                allow_direct: true,
                relays,
                max_hops: maximum,
            },
        }))?;
        Ok(VerifiedNetworkPath::from_grants(
            &self.context(3000),
            members,
            connection,
            verify_network_grant(&signed, &self.context(3000))?,
            [42; 32],
        )?)
    }
}

#[test]
fn mutual_live_observations_choose_two_relays_without_extending_original_deadline() -> Result {
    let f = Fixture::new()?;
    let a = f.ad(0, 1, &[(1, true, 4, 7)], 9000)?;
    let b = f.ad(1, 1, &[(0, true, 7, 4)], 8000)?;
    let mut graph = f.full_graph(&[&a, &b])?;
    let path = f.path(2, vec![f.peers[0], f.peers[1]])?;
    let source = f.endpoint(0, vec![f.peers[0]])?;
    let destination = f.endpoint(1, vec![f.peers[1]])?;
    let candidate = graph
        .candidate(&f.context(3000), &path, &source, &destination)?
        .ok_or("missing mutual candidate")?;
    assert_eq!(candidate.relays(), &[f.peers[0], f.peers[1]]);
    assert_eq!(candidate.cursor(), 7);
    assert_eq!(candidate.expires_at_ms(), 8000);
    graph.apply(
        &f.context(3500),
        &f.full(3500, 7, &[&a, &b])?,
        &[a.verified.clone(), b.verified.clone()],
    )?;
    assert_eq!(
        graph
            .candidate(&f.context(3500), &path, &source, &destination)?
            .ok_or("lost exact snapshot")?
            .expires_at_ms(),
        8000
    );
    graph.expire(&f.context(8000))?;
    assert_eq!(graph.active_publishers(), 1);
    assert_eq!(graph.retained_publishers(), 2);
    assert!(
        graph
            .candidate(&f.context(8000), &path, &source, &destination)?
            .is_none()
    );
    assert!(graph.expire(&f.context(7999)).is_err());
    Ok(())
}

#[test]
fn one_sided_down_or_revision_mismatched_observations_do_not_connect_relays() -> Result {
    let f = Fixture::new()?;
    let a = f.ad(0, 1, &[(1, true, 4, 7)], 9000)?;
    let path = f.path(2, vec![f.peers[0], f.peers[1]])?;
    let source = f.endpoint(0, vec![f.peers[0]])?;
    let destination = f.endpoint(1, vec![f.peers[1]])?;
    for neighbors in [
        vec![],
        vec![(0, false, 7, 4)],
        vec![(0, true, 8, 4)],
        vec![(0, true, 7, 5)],
    ] {
        let b = f.ad(1, 1, &neighbors, 9000)?;
        let mut graph = f.full_graph(&[&a, &b])?;
        assert!(
            graph
                .candidate(&f.context(3000), &path, &source, &destination)?
                .is_none()
        );
    }
    Ok(())
}

#[test]
fn withdrawal_partition_and_new_sequence_recovery_keep_old_sequences_retired() -> Result {
    let f = Fixture::new()?;
    let a = f.ad(0, 1, &[], 9000)?;
    let mut graph = f.full_graph(&[&a])?;
    let path = f.path(1, vec![f.peers[0]])?;
    let source = f.endpoint(0, vec![f.peers[0]])?;
    let destination = f.endpoint(1, vec![f.peers[0]])?;
    graph.apply(
        &f.context(3100),
        &f.delta(3100, 7, vec![a.withdrawal()])?,
        &[],
    )?;
    assert!(
        graph
            .candidate(&f.context(3100), &path, &source, &destination)?
            .is_none()
    );
    assert_eq!(
        (graph.active_publishers(), graph.retained_publishers()),
        (0, 1)
    );
    for cursor in [8, 9] {
        assert!(
            graph
                .apply(
                    &f.context(3200),
                    &f.full(3200, cursor, &[&a])?,
                    std::slice::from_ref(&a.verified)
                )
                .is_err()
        );
        assert_eq!(graph.cursor(), Some(8));
    }
    let b = f.ad(0, 2, &[], 9000)?;
    graph.apply(
        &f.context(3300),
        &f.delta(3300, 8, vec![TopologyChange::Upsert(b.signed.clone())])?,
        std::slice::from_ref(&b.verified),
    )?;
    assert!(
        graph
            .candidate(&f.context(3300), &path, &source, &destination)?
            .is_some()
    );
    assert!(
        graph
            .apply(
                &f.context(3400),
                &f.delta(3400, 9, vec![TopologyChange::Upsert(a.signed.clone())])?,
                std::slice::from_ref(&a.verified)
            )
            .is_err()
    );
    assert_eq!((graph.cursor(), graph.active_publishers()), (Some(9), 1));
    Ok(())
}

#[test]
fn cursor_failures_and_late_invalid_changes_leave_the_original_graph_atomic() -> Result {
    let f = Fixture::new()?;
    let a = f.ad(0, 1, &[], 9000)?;
    let b = f.ad(0, 2, &[], 9000)?;
    let mut graph = TopologyGraph::new(&f.context(3000))?;
    assert!(
        graph
            .apply(
                &f.context(3000),
                &f.delta(3000, 0, vec![a.withdrawal()])?,
                &[]
            )
            .is_err()
    );
    graph.apply(
        &f.context(3000),
        &f.full(3000, 7, &[&a])?,
        std::slice::from_ref(&a.verified),
    )?;
    assert!(
        graph
            .apply(
                &f.context(3100),
                &f.full(3100, 6, &[&a])?,
                std::slice::from_ref(&a.verified)
            )
            .is_err()
    );
    assert!(
        graph
            .apply(
                &f.context(3100),
                &f.full(3100, 7, &[&b])?,
                std::slice::from_ref(&b.verified)
            )
            .is_err()
    );
    assert!(
        graph
            .apply(
                &f.context(3100),
                &f.delta(3100, 6, vec![a.withdrawal()])?,
                &[]
            )
            .is_err()
    );
    let update = f.delta(
        3100,
        7,
        vec![TopologyChange::Upsert(b.signed.clone()), a.withdrawal()],
    )?;
    assert!(
        graph
            .apply(&f.context(3100), &update, std::slice::from_ref(&b.verified))
            .is_err()
    );
    assert_eq!(
        (
            graph.cursor(),
            graph.active_publishers(),
            graph.retained_publishers()
        ),
        (Some(7), 1, 1)
    );
    Ok(())
}

#[test]
fn exact_envelope_proofs_and_absolute_expiry_prevent_unsigned_or_renewed_content() -> Result {
    let f = Fixture::new()?;
    let a = f.ad(0, 1, &[], 9000)?;
    let altered = f.ad(0, 1, &[], 8500)?;
    let mut graph = f.full_graph(&[&a])?;
    assert!(
        graph
            .apply(
                &f.context(3100),
                &f.full(3100, 8, &[&altered])?,
                std::slice::from_ref(&altered.verified)
            )
            .is_err()
    );
    let mut forged = a.signed.clone();
    forged.signature[0] ^= 1;
    let batch = f.update(
        3100,
        TopologySync::Full {
            cursor: 8,
            advertisements: vec![forged],
        },
    )?;
    assert!(
        graph
            .apply(&f.context(3100), &batch, std::slice::from_ref(&a.verified))
            .is_err()
    );
    let b = f.ad(1, 1, &[], 9000)?;
    assert!(
        graph
            .apply(
                &f.context(3100),
                &f.full(3100, 8, &[&a])?,
                &[a.verified.clone(), b.verified]
            )
            .is_err()
    );
    assert!(
        graph
            .apply(&f.context(3100), &f.full(3100, 8, &[&a])?, &[])
            .is_err()
    );
    assert_eq!(graph.cursor(), Some(7));
    Ok(())
}

#[test]
fn expired_historical_upserts_and_withdrawals_advance_without_minting_live_proofs() -> Result {
    let f = Fixture::new()?;
    let a = f.ad(0, 1, &[], 4000)?;
    let mut graph = f.full_graph(&[&a])?;
    graph.expire(&f.context(4000))?;
    let batch = f.delta(
        5000,
        7,
        vec![TopologyChange::Upsert(a.signed.clone()), a.withdrawal()],
    )?;
    graph.apply(&f.context(5000), &batch, &[])?;
    assert_eq!(
        (
            graph.cursor(),
            graph.active_publishers(),
            graph.retained_publishers()
        ),
        (Some(9), 0, 1)
    );
    let mut empty = TopologyGraph::new(&f.context(5000))?;
    empty.apply(&f.context(5000), &f.full(5000, 7, &[&a])?, &[])?;
    assert_eq!(
        (empty.active_publishers(), empty.retained_publishers()),
        (0, 1)
    );
    empty.apply(
        &f.context(5000),
        &f.delta(5000, 7, vec![a.withdrawal()])?,
        &[],
    )?;
    let next = f.ad(0, 2, &[], 9000)?;
    empty.apply(
        &f.context(5000),
        &f.delta(5000, 8, vec![TopologyChange::Upsert(next.signed.clone())])?,
        std::slice::from_ref(&next.verified),
    )?;
    assert_eq!(empty.active_publishers(), 1);
    Ok(())
}

#[test]
fn new_boot_generation_allows_sequence_reset_and_rejects_prior_boot_or_uuid_alias() -> Result {
    let f = Fixture::new()?;
    let old = f.ad(0, 20, &[], 9000)?;
    let next = f.incarnated_ad(0, 1, &[], 9000, boot(2, 91))?;
    let alias = f.incarnated_ad(0, 2, &[], 9000, boot(2, 92))?;
    let mut graph = f.full_graph(&[&old])?;
    graph.apply(
        &f.context(3100),
        &f.full(3100, 8, &[&next])?,
        std::slice::from_ref(&next.verified),
    )?;
    for invalid in [&old, &alias] {
        assert!(
            graph
                .apply(
                    &f.context(3200),
                    &f.full(3200, 9, &[invalid])?,
                    std::slice::from_ref(&invalid.verified)
                )
                .is_err()
        );
    }
    assert_eq!(graph.cursor(), Some(8));
    Ok(())
}

#[test]
fn graph_and_proofs_stay_bound_to_current_authority_scope_epoch_and_revocation() -> Result {
    let mut f = Fixture::new()?;
    let a = f.ad(0, 1, &[], 9000)?;
    let mut graph = f.full_graph(&[&a])?;
    let path = f.path(1, vec![f.peers[0]])?;
    let source = f.endpoint(0, vec![f.peers[0]])?;
    let destination = f.endpoint(1, vec![f.peers[0]])?;
    let other_key = NetworkAuthoritySigner::from_master_seed(&[23; 32])?.public_key();
    let mut context = f.context(3100);
    context.authority_key = &other_key;
    assert!(graph.expire(&context).is_err());
    context = f.context(3100);
    context.space_id = DEPLOYMENT;
    assert!(graph.expire(&context).is_err());
    context = f.context(3100);
    context.policy_epoch = 2;
    assert!(graph.expire(&context).is_err());
    f.revoked.insert(id(501));
    assert!(
        graph
            .candidate(&f.context(3100), &path, &source, &destination)
            .is_err()
    );
    f.revoked.insert(id(200));
    graph.expire(&f.context(3200))?;
    assert_eq!(
        (graph.active_publishers(), graph.retained_publishers()),
        (0, 1)
    );
    Ok(())
}

#[test]
fn signed_hop_limit_and_endpoint_pair_are_checked_after_graph_discovery() -> Result {
    let f = Fixture::new()?;
    let a = f.ad(0, 1, &[(1, true, 4, 7)], 9000)?;
    let b = f.ad(1, 1, &[(0, true, 7, 4)], 9000)?;
    let mut graph = f.full_graph(&[&a, &b])?;
    let source = f.endpoint(0, vec![f.peers[0]])?;
    let destination = f.endpoint(1, vec![f.peers[1]])?;
    assert!(
        graph
            .candidate(
                &f.context(3000),
                &f.path(1, f.peers[..2].to_vec())?,
                &source,
                &destination
            )?
            .is_none()
    );
    assert!(
        graph
            .candidate(&f.context(3000), &f.path(0, vec![])?, &source, &destination)?
            .is_none()
    );
    let wrong = EndpointAttachments::new(PeerId([87; 32]), vec![f.peers[0]])?;
    assert!(
        graph
            .candidate(
                &f.context(3000),
                &f.path(2, f.peers[..2].to_vec())?,
                &wrong,
                &destination
            )
            .is_err()
    );
    let endpoint = PeerId::from_public_key(&f.endpoints[0].public_key());
    assert!(EndpointAttachments::new(endpoint, vec![endpoint]).is_err());
    assert!(EndpointAttachments::new(endpoint, vec![f.peers[0], f.peers[0]]).is_err());
    Ok(())
}

#[test]
fn three_relay_chain_cannot_escape_the_two_relay_protocol_limit() -> Result {
    let f = Fixture::new()?;
    let a = f.ad(0, 1, &[(1, true, 4, 7)], 9000)?;
    let b = f.ad(1, 1, &[(0, true, 7, 4), (2, true, 7, 9)], 9000)?;
    let c = f.ad(2, 1, &[(1, true, 9, 7)], 9000)?;
    let mut graph = f.full_graph(&[&a, &b, &c])?;
    let source = f.endpoint(0, vec![f.peers[0]])?;
    let destination = f.endpoint(1, vec![f.peers[2]])?;
    assert!(
        graph
            .candidate(
                &f.context(3000),
                &f.path(2, f.peers.to_vec())?,
                &source,
                &destination
            )?
            .is_none()
    );
    Ok(())
}

#[test]
fn fewest_hops_then_peer_order_is_deterministic_even_in_a_cyclic_topology() -> Result {
    let f = Fixture::new()?;
    let a = f.ad(0, 1, &[(1, true, 4, 7), (2, true, 4, 9)], 9000)?;
    let b = f.ad(1, 1, &[(0, true, 7, 4), (2, true, 7, 9)], 9000)?;
    let c = f.ad(2, 1, &[(0, true, 9, 4), (1, true, 9, 7)], 9000)?;
    let path = f.path(2, f.peers.to_vec())?;
    let source = f.endpoint(0, f.peers.to_vec())?;
    let destination = f.endpoint(1, f.peers.to_vec())?;
    for order in [[&a, &b, &c], [&c, &a, &b]] {
        let mut graph = f.full_graph(&order)?;
        let selected = graph
            .candidate(&f.context(3000), &path, &source, &destination)?
            .ok_or("missing one-hop candidate")?;
        let first = *f.peers.iter().min().ok_or("missing fixture relay")?;
        assert_eq!(selected.relays(), &[first]);
        let destination = f.endpoint(1, vec![f.peers[2]])?;
        let source = f.endpoint(0, f.peers[..2].to_vec())?;
        let selected = graph
            .candidate(&f.context(3000), &path, &source, &destination)?
            .ok_or("missing two-hop candidate")?;
        assert_eq!(selected.relays(), &[f.peers[0].min(f.peers[1]), f.peers[2]]);
    }
    Ok(())
}

#[test]
fn full_omission_preserves_fences_and_expired_updates_cannot_remove_current_observations() -> Result
{
    let f = Fixture::new()?;
    let a = f.ad(0, 1, &[], 9000)?;
    let mut graph = f.full_graph(&[&a])?;
    let stale = f.full(3000, 8, &[])?;
    assert!(graph.apply(&f.context(4000), &stale, &[]).is_err());
    assert_eq!(graph.active_publishers(), 1);
    graph.apply(&f.context(4000), &f.full(4000, 8, &[])?, &[])?;
    assert_eq!(
        (graph.active_publishers(), graph.retained_publishers()),
        (0, 1)
    );
    assert!(
        graph
            .apply(
                &f.context(4100),
                &f.full(4100, 9, &[&a])?,
                std::slice::from_ref(&a.verified)
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn candidates_wait_for_the_last_delta_page_and_full_snapshots_restore_completeness() -> Result {
    let f = Fixture::new()?;
    let a = f.ad(0, 1, &[], 9000)?;
    let b = f.ad(1, 1, &[], 9000)?;
    let mut graph = f.full_graph(&[&a, &b])?;
    let path = f.path(1, vec![f.peers[0]])?;
    let source = f.endpoint(0, vec![f.peers[0]])?;
    let destination = f.endpoint(1, vec![f.peers[0]])?;
    assert!(!graph.needs_more());
    assert!(
        graph
            .candidate(&f.context(3000), &path, &source, &destination)?
            .is_some()
    );
    let first_page = f.update(
        3100,
        TopologySync::Delta {
            after_cursor: 7,
            cursor: 8,
            has_more: true,
            changes: vec![TopologyDeltaEntry {
                cursor: 8,
                change: b.withdrawal(),
            }],
        },
    )?;
    graph.apply(&f.context(3100), &first_page, &[])?;
    assert!(graph.needs_more());
    assert_eq!((graph.cursor(), graph.active_publishers()), (Some(8), 1));
    assert!(
        graph
            .candidate(&f.context(3100), &path, &source, &destination)?
            .is_none()
    );
    // A failed last page cannot mark the partially synchronized graph ready.
    assert!(
        graph
            .apply(
                &f.context(3200),
                &f.delta(3200, 7, vec![a.withdrawal()])?,
                &[]
            )
            .is_err()
    );
    assert!(graph.needs_more());
    graph.apply(
        &f.context(3300),
        &f.delta(3300, 8, vec![a.withdrawal()])?,
        &[],
    )?;
    assert!(!graph.needs_more());
    assert!(
        graph
            .candidate(&f.context(3300), &path, &source, &destination)?
            .is_none()
    );
    let next = f.ad(0, 2, &[], 9000)?;
    let page = f.update(
        3400,
        TopologySync::Delta {
            after_cursor: 9,
            cursor: 10,
            has_more: true,
            changes: vec![TopologyDeltaEntry {
                cursor: 10,
                change: TopologyChange::Upsert(next.signed.clone()),
            }],
        },
    )?;
    graph.apply(
        &f.context(3400),
        &page,
        std::slice::from_ref(&next.verified),
    )?;
    assert!(graph.needs_more());
    graph.apply(
        &f.context(3500),
        &f.full(3500, 10, &[&next])?,
        std::slice::from_ref(&next.verified),
    )?;
    assert!(!graph.needs_more());
    assert!(
        graph
            .candidate(&f.context(3500), &path, &source, &destination)?
            .is_some()
    );
    Ok(())
}

#[test]
fn failed_batches_preserve_trusted_time_expiry_and_revocation_fences() -> Result {
    let mut f = Fixture::new()?;
    let a = f.ad(0, 1, &[], 4000)?;
    let b = f.ad(1, 1, &[], 9000)?;
    let path = f.path(1, vec![f.peers[0]])?;
    let source = f.endpoint(0, vec![f.peers[0]])?;
    let destination = f.endpoint(1, vec![f.peers[0]])?;
    for batch in [f.full(3000, 8, &[])?, f.full(5000, 8, &[&b])?] {
        let mut graph = f.full_graph(&[&a])?;
        assert!(graph.apply(&f.context(5000), &batch, &[]).is_err());
        assert_eq!(
            (
                graph.cursor(),
                graph.active_publishers(),
                graph.retained_publishers()
            ),
            (Some(7), 0, 1)
        );
        assert!(
            graph
                .candidate(&f.context(3500), &path, &source, &destination)
                .is_err()
        );
        assert!(graph.expire(&f.context(4999)).is_err());
        assert!(
            graph
                .apply(&f.context(5000), &f.full(5000, 8, &[&a])?, &[])
                .is_ok()
        );
        assert_eq!(graph.active_publishers(), 0);
    }
    let mut graph = f.full_graph(&[&b])?;
    f.revoked.insert(id(201));
    assert!(
        graph
            .apply(&f.context(3500), &f.full(2000, 8, &[])?, &[])
            .is_err()
    );
    assert_eq!(graph.active_publishers(), 0);
    f.revoked.clear();
    assert!(
        graph
            .apply(
                &f.context(3600),
                &f.full(3600, 8, &[&b])?,
                std::slice::from_ref(&b.verified)
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn retained_publisher_budget_is_bounded_and_overflow_is_atomic() -> Result {
    let f = Fixture::new()?;
    let mut graph = TopologyGraph::new(&f.context(3000))?;
    graph.apply(&f.context(3000), &f.full(3000, 0, &[])?, &[])?;
    for start in (0..MAX_GRAPH_NODES).step_by(256) {
        let changes = (start..(start + 256).min(MAX_GRAPH_NODES))
            .map(|index| {
                let mut peer = [0u8; 32];
                peer[..8].copy_from_slice(&(index as u64 + 1).to_be_bytes());
                TopologyChange::Withdraw(TopologyWithdrawal {
                    node_id: id(1000 + index as u64),
                    peer: PeerId(peer),
                    publisher_digest: [1; 32],
                    incarnation: boot(1, 90),
                    sequence: 1,
                })
            })
            .collect();
        graph.apply(
            &f.context(3000),
            &f.delta(3000, start as u64, changes)?,
            &[],
        )?;
    }
    assert_eq!(graph.retained_publishers(), MAX_GRAPH_NODES);
    let excess = TopologyChange::Withdraw(TopologyWithdrawal {
        node_id: id(9999),
        peer: PeerId([255; 32]),
        publisher_digest: [1; 32],
        incarnation: boot(1, 90),
        sequence: 1,
    });
    assert!(
        graph
            .apply(
                &f.context(3000),
                &f.delta(3000, MAX_GRAPH_NODES as u64, vec![excess])?,
                &[]
            )
            .is_err()
    );
    assert_eq!(graph.cursor(), Some(MAX_GRAPH_NODES as u64));
    assert_eq!(graph.retained_publishers(), MAX_GRAPH_NODES);
    Ok(())
}

#[test]
fn a_rejected_newer_authenticated_view_cannot_reopen_candidates_from_an_older_snapshot() -> Result {
    let f = Fixture::new()?;
    let a = f.ad(0, 1, &[], 9000)?;
    let b = f.ad(1, 1, &[], 9000)?;
    let mut graph = f.full_graph(&[&a])?;
    let path = f.path(1, vec![f.peers[0]])?;
    let source = f.endpoint(0, vec![f.peers[0]])?;
    let destination = f.endpoint(1, vec![f.peers[0]])?;
    // Contents fail atomically because B's original live proof is missing,
    // but the authority has proved the existence of newer cursor 9.
    assert!(
        graph
            .apply(
                &f.context(3100),
                &f.full(3100, 9, &[&a, &b])?,
                std::slice::from_ref(&a.verified)
            )
            .is_err()
    );
    assert_eq!(graph.cursor(), Some(7));
    assert!(graph.needs_more());
    assert!(
        graph
            .candidate(&f.context(3100), &path, &source, &destination)?
            .is_none()
    );
    graph.apply(
        &f.context(3200),
        &f.full(3200, 8, &[&a])?,
        std::slice::from_ref(&a.verified),
    )?;
    assert!(graph.needs_more());
    assert!(
        graph
            .candidate(&f.context(3200), &path, &source, &destination)?
            .is_none()
    );
    graph.apply(
        &f.context(3300),
        &f.full(3300, 9, &[&a])?,
        std::slice::from_ref(&a.verified),
    )?;
    assert!(!graph.needs_more());
    assert!(
        graph
            .candidate(&f.context(3300), &path, &source, &destination)?
            .is_some()
    );
    Ok(())
}
