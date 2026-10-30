use ed25519_dalek::{Signer, SigningKey};
use nestlink_identity::{
    network::{
        NetworkAuthoritySigner, NetworkVerification, VerifiedNetworkGrant, verify_network_grant,
    },
    network_topology::*,
    nodes::NodeIdentity,
};
use nestlink_protocol::{
    network::{GrantClaims, GrantScope, IpPrefix, PeerId, RouteExportClaims},
    network_topology::*,
};
use std::collections::BTreeSet;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const DEPLOYMENT: &str = "51fdac9e-235d-4688-8783-239f97457606";
const SPACE: &str = "f0c1429b-167b-4f87-897e-606f934e42ca";
const NODE: &str = "354ee49b-1873-4ca8-b978-afaf03f9d964";
const NODE_SEED: [u8; 32] = [17; 32];

struct Fixture {
    authority: NetworkAuthoritySigner,
    key: [u8; 32],
    node: NodeIdentity,
    incarnation: BootIncarnation,
    claims: TopologyPublisherClaims,
    publisher: SignedTopologyPublisher,
    exports: Vec<VerifiedNetworkGrant>,
    revoked: BTreeSet<String>,
}
impl Fixture {
    fn new(prefix: bool) -> Result<Self> {
        let authority = NetworkAuthoritySigner::from_master_seed(&[8; 32])?;
        let key = authority.public_key();
        let node = NodeIdentity::from_seed(&NODE_SEED);
        let peer = PeerId::from_public_key(&node.public_key());
        let incarnation = BootIncarnation {
            runtime_generation: 1,
            runtime_id: "1e1b93be-4dc0-46f7-9091-65ac7f0f6f69".into(),
        };
        let mut claims = TopologyPublisherClaims {
            scope: scope("f37332b6-59f7-48c2-b532-82ad0894f165"),
            node_id: NODE.into(),
            public_key: node.public_key(),
            peer,
            incarnation: incarnation.clone(),
            allowed_neighbors: vec![PeerId([3; 32])],
            route_export_digests: vec![],
            allowed_prefixes: vec![],
        };
        let revoked = BTreeSet::new();
        let mut exports = vec![];
        if prefix {
            let export = authority.sign(&GrantClaims::RouteExport(RouteExportClaims {
                scope: scope("7c3e47ec-d553-446c-a51a-dc811668cb64"),
                gateway: peer,
                prefixes: vec![IpPrefix {
                    network: "10.40.0.0".parse()?,
                    prefix_len: 24,
                }],
            }))?;
            let context = NetworkVerification {
                authority_key: &key,
                deployment_id: DEPLOYMENT,
                space_id: SPACE,
                policy_epoch: 1,
                now_ms: 3000,
                revoked_grant_ids: &revoked,
            };
            let export = verify_network_grant(&export, &context)?;
            claims.route_export_digests.push(export.digest());
            claims.allowed_prefixes.push(IpPrefix {
                network: "10.40.0.0".parse()?,
                prefix_len: 24,
            });
            exports.push(export);
        }
        let publisher = authority.sign_topology_publisher(&claims)?;
        Ok(Self {
            authority,
            key,
            node,
            incarnation,
            claims,
            publisher,
            exports,
            revoked,
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
    fn verified_publisher(&self, now_ms: u64) -> Result<VerifiedTopologyPublisher> {
        Ok(verify_topology_publisher(
            &self.publisher,
            &self.context(now_ms),
            NODE,
            &self.node.public_key(),
            &self.incarnation,
            &self.exports,
        )?)
    }
    fn report(&self, publisher: &VerifiedTopologyPublisher) -> TopologyReport {
        TopologyReport {
            schema_version: SCHEMA_VERSION,
            deployment_id: DEPLOYMENT.into(),
            space_id: SPACE.into(),
            policy_epoch: 1,
            node_id: NODE.into(),
            peer: self.claims.peer,
            publisher_digest: publisher.digest(),
            incarnation: self.incarnation.clone(),
            sequence: 1,
            not_before_ms: 2000,
            expires_at_ms: 9000,
            neighbors: vec![TopologyNeighbor {
                local: self.claims.peer,
                remote: self.claims.allowed_neighbors[0],
                local_endpoint_revision: 4,
                remote_endpoint_revision: 7,
                up: true,
            }],
            prefixes: self.claims.allowed_prefixes.clone(),
        }
    }
}
fn scope(grant_id: &str) -> GrantScope {
    GrantScope {
        schema_version: 1,
        deployment_id: DEPLOYMENT.into(),
        space_id: SPACE.into(),
        grant_id: grant_id.into(),
        policy_epoch: 1,
        not_before_ms: 1000,
        expires_at_ms: 20_000,
    }
}

#[test]
fn node_report_and_authority_advertisement_keep_original_permission_and_deadline() -> Result {
    let f = Fixture::new(true)?;
    let publisher = f.verified_publisher(3000)?;
    let report = f.node.sign_topology_report(&f.report(&publisher))?;
    let verified =
        verify_topology_report(&report, &publisher, &f.context(3000), &f.incarnation, 0)?;
    let advertisement = f
        .authority
        .sign_topology_advertisement(&verified, 3000, 50_000)?;
    let admitted = verify_topology_advertisement(
        &advertisement,
        &publisher,
        &f.context(3000),
        &f.incarnation,
        0,
    )?;
    assert_eq!(admitted.claims().expires_at_ms, 9000);
    assert_eq!(admitted.claims().report_digest, verified.digest());
    assert_eq!(admitted.claims().report_signature, report.signature);
    assert!(
        f.authority
            .sign_topology_advertisement(&verified, 9000, 50_000)
            .is_err()
    );
    assert!(
        NetworkAuthoritySigner::from_master_seed(&[9; 32])?
            .sign_topology_advertisement(&verified, 3000, 8000)
            .is_err()
    );
    assert!(
        verify_topology_advertisement(
            &advertisement,
            &publisher,
            &f.context(9000),
            &f.incarnation,
            0,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn reports_reject_cross_scope_replay_old_incarnation_and_unauthorized_neighbors() -> Result {
    let f = Fixture::new(false)?;
    let publisher = f.verified_publisher(3000)?;
    let report = f.report(&publisher);
    let valid = f.node.sign_topology_report(&report)?;
    assert!(
        verify_topology_report(&valid, &publisher, &f.context(3000), &f.incarnation, 1).is_err()
    );
    let mut wrong_space = report.clone();
    wrong_space.space_id = "ef161eff-232a-4c84-8e18-cb8922857cad".into();
    let mut wrong_deployment = report.clone();
    wrong_deployment.deployment_id = wrong_space.space_id.clone();
    let mut wrong_boot = report.clone();
    wrong_boot.incarnation.runtime_generation += 1;
    let mut wrong_neighbor = report.clone();
    wrong_neighbor.neighbors[0].remote = PeerId([6; 32]);
    let mut wrong_epoch = report.clone();
    wrong_epoch.policy_epoch += 1;
    let mut expired = report.clone();
    expired.expires_at_ms = 3000;
    for forged in [
        wrong_space,
        wrong_deployment,
        wrong_boot,
        wrong_neighbor,
        wrong_epoch,
        expired,
    ] {
        let signed = f.node.sign_topology_report(&forged)?;
        assert!(
            verify_topology_report(&signed, &publisher, &f.context(3000), &f.incarnation, 0)
                .is_err()
        );
    }
    let mut future_boot = f.incarnation.clone();
    future_boot.runtime_generation += 1;
    assert!(
        publisher
            .check_current(&f.context(3000), &future_boot)
            .is_err()
    );
    assert!(f.verified_publisher(20_000).is_err());
    Ok(())
}

#[test]
fn signatures_are_node_pinned_domain_separated_canonical_and_bounded() -> Result {
    let f = Fixture::new(false)?;
    let publisher = f.verified_publisher(3000)?;
    let claims = f.report(&publisher);
    let mut tampered = f.node.sign_topology_report(&claims)?;
    tampered.signature[0] ^= 1;
    assert!(
        verify_topology_report(&tampered, &publisher, &f.context(3000), &f.incarnation, 0).is_err()
    );
    let mut wrong_purpose = f.node.sign_topology_report(&claims)?;
    let mut message = b"NestLink/network-topology/v1/publisher\0".to_vec();
    message.extend_from_slice(&(wrong_purpose.claims.len() as u32).to_be_bytes());
    message.extend_from_slice(&wrong_purpose.claims);
    wrong_purpose.signature = SigningKey::from_bytes(&NODE_SEED)
        .sign(&message)
        .to_bytes()
        .to_vec();
    assert!(
        verify_topology_report(
            &wrong_purpose,
            &publisher,
            &f.context(3000),
            &f.incarnation,
            0
        )
        .is_err()
    );
    assert!(
        verify_topology_publisher(
            &f.publisher,
            &f.context(3000),
            NODE,
            &[99; 32],
            &f.incarnation,
            &[],
        )
        .is_err()
    );
    let mut duplicate = f.node.sign_topology_report(&claims)?;
    let text = String::from_utf8(duplicate.claims)?;
    duplicate.claims = text.replacen('{', "{\"schema_version\":1,", 1).into_bytes();
    assert!(
        verify_topology_report(&duplicate, &publisher, &f.context(3000), &f.incarnation, 0)
            .is_err()
    );
    duplicate.claims = vec![b' '; MAX_REPORT_BYTES + 1];
    assert!(
        verify_topology_report(&duplicate, &publisher, &f.context(3000), &f.incarnation, 0)
            .is_err()
    );
    Ok(())
}

#[test]
fn prefixes_need_the_current_exact_export_chain_and_never_accept_default_routes() -> Result {
    let mut f = Fixture::new(true)?;
    let publisher = f.verified_publisher(3000)?;
    assert!(
        verify_topology_publisher(
            &f.publisher,
            &f.context(3000),
            NODE,
            &f.node.public_key(),
            &f.incarnation,
            &[],
        )
        .is_err()
    );
    let mut report = f.report(&publisher);
    report.prefixes[0].network = "10.41.0.0".parse()?;
    assert!(
        verify_topology_report(
            &f.node.sign_topology_report(&report)?,
            &publisher,
            &f.context(3000),
            &f.incarnation,
            0,
        )
        .is_err()
    );
    report.prefixes[0] = IpPrefix {
        network: "0.0.0.0".parse()?,
        prefix_len: 0,
    };
    assert!(f.node.sign_topology_report(&report).is_err());
    let GrantClaims::RouteExport(export) = f.exports[0].claims() else {
        return Err("fixture RouteExport missing".into());
    };
    f.revoked.insert(export.scope.grant_id.clone());
    assert!(
        publisher
            .check_current(&f.context(3000), &f.incarnation)
            .is_err()
    );
    Ok(())
}

#[test]
fn authority_signed_withdrawal_survives_report_expiry_and_binds_query_and_cursor() -> Result {
    let f = Fixture::new(false)?;
    let publisher = f.verified_publisher(3000)?;
    let update = TopologyUpdate {
        schema_version: SCHEMA_VERSION,
        deployment_id: DEPLOYMENT.into(),
        space_id: SPACE.into(),
        policy_epoch: 1,
        query_nonce: [5; 32],
        issued_at_ms: 11_000,
        expires_at_ms: 13_000,
        sync: TopologySync::Delta {
            after_cursor: 7,
            cursor: 8,
            has_more: false,
            changes: vec![TopologyDeltaEntry {
                cursor: 8,
                change: TopologyChange::Withdraw(TopologyWithdrawal {
                    node_id: NODE.into(),
                    peer: f.claims.peer,
                    publisher_digest: publisher.digest(),
                    incarnation: f.incarnation.clone(),
                    sequence: 1,
                }),
            }],
        },
    };
    let signed = f.authority.sign_topology_update(&update)?;
    let verified = verify_topology_update(&signed, &f.context(12_000), &[5; 32])?;
    assert_eq!(verified.claims(), &update);
    assert!(verify_topology_update(&signed, &f.context(12_000), &[6; 32]).is_err());
    assert!(verify_topology_update(&signed, &f.context(13_000), &[5; 32]).is_err());
    let mut context = f.context(12_000);
    context.space_id = "ef161eff-232a-4c84-8e18-cb8922857cad";
    assert!(verify_topology_update(&signed, &context, &[5; 32]).is_err());
    let mut forged = signed;
    forged.signature[0] ^= 1;
    assert!(verify_topology_update(&forged, &f.context(12_000), &[5; 32]).is_err());
    Ok(())
}

#[test]
fn verified_observation_metadata_binds_exact_envelopes_and_rechecks_current_authority() -> Result {
    let f = Fixture::new(false)?;
    let publisher = f.verified_publisher(3000)?;
    let report = f.node.sign_topology_report(&f.report(&publisher))?;
    let report = verify_topology_report(&report, &publisher, &f.context(3000), &f.incarnation, 0)?;
    let signed = f
        .authority
        .sign_topology_advertisement(&report, 3000, 9000)?;
    let advertisement =
        verify_topology_advertisement(&signed, &publisher, &f.context(3000), &f.incarnation, 0)?;
    assert_eq!(
        advertisement.envelope_digest(),
        nestlink_identity::digest(&signed.canonical_bytes()?)
    );
    let mut tampered = signed.clone();
    tampered.signature[0] ^= 1;
    assert_ne!(
        advertisement.envelope_digest(),
        nestlink_identity::digest(&tampered.canonical_bytes()?)
    );
    assert!(
        verify_topology_advertisement(&tampered, &publisher, &f.context(3000), &f.incarnation, 0,)
            .is_err()
    );
    let update = TopologyUpdate {
        schema_version: SCHEMA_VERSION,
        deployment_id: DEPLOYMENT.into(),
        space_id: SPACE.into(),
        policy_epoch: 1,
        query_nonce: [7; 32],
        issued_at_ms: 3000,
        expires_at_ms: 4000,
        sync: TopologySync::Full {
            cursor: 1,
            advertisements: vec![signed],
        },
    };
    let signed = f.authority.sign_topology_update(&update)?;
    let verified = verify_topology_update(&signed, &f.context(3000), &[7; 32])?;
    assert_eq!(
        verified.envelope_digest(),
        nestlink_identity::digest(&signed.canonical_bytes()?)
    );
    let other_key = NetworkAuthoritySigner::from_master_seed(&[9; 32])?.public_key();
    let mut context = f.context(3000);
    context.authority_key = &other_key;
    assert!(advertisement.check_current(&context).is_err());
    assert!(verified.check_current(&context).is_err());
    context = f.context(3000);
    context.space_id = DEPLOYMENT;
    assert!(advertisement.check_current(&context).is_err());
    assert!(verified.check_current(&context).is_err());
    context = f.context(3000);
    context.policy_epoch += 1;
    assert!(advertisement.check_current(&context).is_err());
    assert!(verified.check_current(&context).is_err());
    assert!(advertisement.check_current(&f.context(9000)).is_err());
    assert!(verified.check_current(&f.context(4000)).is_err());
    Ok(())
}

#[test]
fn verified_advertisement_projection_retains_all_current_publication_revocations() -> Result {
    let mut f = Fixture::new(true)?;
    let publisher = f.verified_publisher(3000)?;
    let report = f.node.sign_topology_report(&f.report(&publisher))?;
    let report = verify_topology_report(&report, &publisher, &f.context(3000), &f.incarnation, 0)?;
    let signed = f
        .authority
        .sign_topology_advertisement(&report, 3000, 9000)?;
    let advertisement =
        verify_topology_advertisement(&signed, &publisher, &f.context(3000), &f.incarnation, 0)?;
    let ids = advertisement.publication_grant_ids();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&f.claims.scope.grant_id));
    assert!(ids.contains(&f.exports[0].claims().scope().grant_id));
    for id in ids {
        f.revoked.insert(id.clone());
        assert!(advertisement.check_current(&f.context(3000)).is_err());
        f.revoked.remove(&id);
    }
    advertisement.check_current(&f.context(3000))?;
    Ok(())
}

#[test]
fn publisher_proof_budget_and_projection_do_not_expand_duplicate_export_credentials() -> Result {
    let f = Fixture::new(true)?;
    let exports = vec![f.exports[0].clone(); nestlink_protocol::network_topology::MAX_PREFIXES];
    let publisher = verify_topology_publisher(
        &f.publisher,
        &f.context(3000),
        NODE,
        &f.node.public_key(),
        &f.incarnation,
        &exports,
    )?;
    let report = f.node.sign_topology_report(&f.report(&publisher))?;
    let report = verify_topology_report(&report, &publisher, &f.context(3000), &f.incarnation, 0)?;
    let signed = f
        .authority
        .sign_topology_advertisement(&report, 3000, 9000)?;
    let advertisement =
        verify_topology_advertisement(&signed, &publisher, &f.context(3000), &f.incarnation, 0)?;
    let ids = advertisement.publication_grant_ids();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&f.claims.scope.grant_id));
    assert!(ids.contains(&f.exports[0].claims().scope().grant_id));
    let oversized =
        vec![f.exports[0].clone(); nestlink_protocol::network_topology::MAX_PREFIXES + 1];
    assert_eq!(
        verify_topology_publisher(
            &f.publisher,
            &f.context(3000),
            NODE,
            &f.node.public_key(),
            &f.incarnation,
            &oversized,
        )
        .err()
        .map(|error| error.code),
        Some(nestlink_protocol::ErrorCode::CapacityExceeded)
    );
    Ok(())
}
