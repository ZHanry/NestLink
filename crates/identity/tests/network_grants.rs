use nestlink_identity::network::*;
use nestlink_protocol::{ContractError, ErrorCode, network::*};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

fn membership() -> GrantClaims {
    let public_key = [9; 32];
    GrantClaims::Membership(MembershipClaims {
        scope: GrantScope {
            schema_version: 1,
            deployment_id: "10000000-0000-4000-8000-000000000001".into(),
            space_id: "20000000-0000-4000-8000-000000000002".into(),
            grant_id: "30000000-0000-4000-8000-000000000003".into(),
            policy_epoch: 7, not_before_ms: 1000, expires_at_ms: 2000,
        },
        installation_id: "40000000-0000-4000-8000-000000000004".into(),
        peer: PeerId::from_public_key(&public_key), public_key, membership_epoch: 3, role: SpaceRole::Owner,
    })
}

#[test]
fn signed_membership_rejects_copying_to_a_different_device_or_epoch()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = NetworkAuthoritySigner::from_master_seed(&[42; 32])?;
    let key = signer.public_key();
    let revoked = BTreeSet::new();
    let context = NetworkVerification {
        authority_key: &key, deployment_id: "10000000-0000-4000-8000-000000000001",
        space_id: "20000000-0000-4000-8000-000000000002", policy_epoch: 7, now_ms: 1500,
        revoked_grant_ids: &revoked,
    };
    let signed = signer.sign(&membership())?;
    let verified = verify_network_grant(&signed, &context)?;
    assert_eq!(verified.expect_member(&context, "40000000-0000-4000-8000-000000000004", &[9; 32], 3)?, PeerId::from_public_key(&[9; 32]));
    assert!(verified.expect_member(&context, "40000000-0000-4000-8000-000000000005", &[9; 32], 3).is_err());
    assert!(verified.expect_member(&context, "40000000-0000-4000-8000-000000000004", &[8; 32], 3).is_err());
    assert!(verified.expect_member(&context, "40000000-0000-4000-8000-000000000004", &[9; 32], 4).is_err());
    let member = VerifiedMembership::from_grant(verified.clone(), &context,
        "40000000-0000-4000-8000-000000000004", &[9; 32], 3)?;
    assert_eq!(member.peer(), PeerId::from_public_key(&[9; 32]));
    for (installation, public_key, epoch) in [
        ("40000000-0000-4000-8000-000000000005", [9; 32], 3),
        ("40000000-0000-4000-8000-000000000004", [8; 32], 3),
        ("40000000-0000-4000-8000-000000000004", [9; 32], 4),
    ] {
        assert!(VerifiedMembership::from_grant(verified.clone(), &context,
            installation, &public_key, epoch).is_err());
    }
    Ok(())
}

fn verification_context<'a>(key: &'a [u8; 32], revoked: &'a BTreeSet<String>) -> NetworkVerification<'a> {
    NetworkVerification {
        authority_key: key,
        deployment_id: "10000000-0000-4000-8000-000000000001",
        space_id: "20000000-0000-4000-8000-000000000002",
        policy_epoch: 7,
        now_ms: 1500,
        revoked_grant_ids: revoked,
    }
}

fn grant_scope(id: u8) -> GrantScope {
    GrantScope {
        schema_version: 1,
        deployment_id: "10000000-0000-4000-8000-000000000001".into(),
        space_id: "20000000-0000-4000-8000-000000000002".into(),
        grant_id: format!("30000000-0000-4000-8000-{id:012x}"),
        policy_epoch: 7,
        not_before_ms: 1000,
        expires_at_ms: 2000,
    }
}

fn sign_verify(
    signer: &NetworkAuthoritySigner,
    context: &NetworkVerification<'_>,
    claims: GrantClaims,
) -> Result<VerifiedNetworkGrant, ContractError> {
    verify_network_grant(&signer.sign(&claims)?, context)
}

fn bind_member(
    signer: &NetworkAuthoritySigner,
    context: &NetworkVerification<'_>,
    claims: &MembershipClaims,
) -> Result<VerifiedMembership, ContractError> {
    VerifiedMembership::from_grant(
        sign_verify(signer, context, GrantClaims::Membership(claims.clone()))?,
        context,
        &claims.installation_id,
        &claims.public_key,
        claims.membership_epoch,
    )
}

const BUSINESS_DIGEST: [u8; 32] = [71; 32];

#[derive(Clone)]
struct PathFixture {
    members: [MembershipClaims; 2],
    connection: ConnectivityClaims,
    path: PathClaims,
}

#[derive(Clone)]
struct ChainParts {
    members: [VerifiedMembership; 2],
    connection: VerifiedNetworkGrant,
    path: VerifiedNetworkGrant,
}

impl ChainParts {
    fn build(self, context: &NetworkVerification<'_>) -> Result<VerifiedNetworkPath, ContractError> {
        VerifiedNetworkPath::from_grants(context, self.members, self.connection, self.path, BUSINESS_DIGEST)
    }
}

impl PathFixture {
    fn new(signer: &NetworkAuthoritySigner, context: &NetworkVerification<'_>) -> Result<Self, ContractError> {
        let member = |id: u8| {
            let public_key = [id; 32];
            MembershipClaims {
                scope: grant_scope(id),
                installation_id: format!("40000000-0000-4000-8000-{id:012x}"),
                peer: PeerId::from_public_key(&public_key),
                public_key,
                membership_epoch: 3,
                role: SpaceRole::Member,
            }
        };
        let mut members = [member(10), member(11)];
        if members[0].peer > members[1].peer { members.swap(0, 1); }
        let peers = PeerPair::new(members[0].peer, members[1].peer)?;
        let mut connection_scope = grant_scope(12);
        connection_scope.not_before_ms = 1100;
        connection_scope.expires_at_ms = 1900;
        let connection = ConnectivityClaims {
            scope: connection_scope,
            peers,
            purpose: Purpose::RemoteControl,
            membership_digests: [[1; 32], [2; 32]],
            business_grant_digest: BUSINESS_DIGEST,
        };
        let mut path_scope = grant_scope(13);
        path_scope.not_before_ms = 1200;
        path_scope.expires_at_ms = 1800;
        let path = PathClaims {
            scope: path_scope,
            peers,
            purpose: Purpose::RemoteControl,
            connectivity_grant_digest: [3; 32],
            policy: PathPolicy {
                allow_direct: true,
                relays: vec![PeerId::from_public_key(&[20; 32])],
                max_hops: 1,
            },
        };
        let mut fixture = Self { members, connection, path };
        fixture.refresh_references(signer, context)?;
        Ok(fixture)
    }

    fn refresh_references(&mut self, signer: &NetworkAuthoritySigner, context: &NetworkVerification<'_>)
        -> Result<(), ContractError> {
        self.connection.membership_digests = [
            bind_member(signer, context, &self.members[0])?.digest(),
            bind_member(signer, context, &self.members[1])?.digest(),
        ];
        self.path.connectivity_grant_digest =
            sign_verify(signer, context, GrantClaims::Connectivity(self.connection.clone()))?.digest();
        Ok(())
    }

    fn parts(&self, signer: &NetworkAuthoritySigner, context: &NetworkVerification<'_>)
        -> Result<ChainParts, ContractError> {
        Ok(ChainParts {
            members: [bind_member(signer, context, &self.members[0])?, bind_member(signer, context, &self.members[1])?],
            connection: sign_verify(signer, context, GrantClaims::Connectivity(self.connection.clone()))?,
            path: sign_verify(signer, context, GrantClaims::Path(self.path.clone()))?,
        })
    }
}

#[test]
fn digests_bind_the_issuer_and_verified_transport_group_uses_its_own_domain()
    -> Result<(), Box<dyn std::error::Error>> {
    let signer = NetworkAuthoritySigner::from_master_seed(&[42; 32])?;
    let second_signer = NetworkAuthoritySigner::from_master_seed(&[43; 32])?;
    let key = signer.public_key();
    let second_key = second_signer.public_key();
    let revoked = BTreeSet::new();
    let context = verification_context(&key, &revoked);
    let second_context = NetworkVerification { authority_key: &second_key, ..verification_context(&key, &revoked) };
    let claims = membership();
    let first = sign_verify(&signer, &context, claims.clone())?;
    let second = sign_verify(&second_signer, &second_context, claims.clone())?;
    assert_ne!(first.digest(), second.digest());
    let mut reference = b"NestLink/network/v1/grant-digest\0".to_vec();
    reference.extend_from_slice(&key);
    reference.extend_from_slice(&claims.signing_message()?);
    assert_eq!(first.digest(), <[u8; 32]>::from(Sha256::digest(&reference)));
    assert_ne!(first.digest(), <[u8; 32]>::from(Sha256::digest(claims.signing_message()?)));
    let fixture = PathFixture::new(&signer, &context)?;
    let verified = fixture.parts(&signer, &context)?.build(&context)?;
    let mut group = b"NestLink/network/v1/transport-group\0".to_vec();
    group.extend_from_slice(&key);
    group.extend_from_slice(&GrantClaims::Path(fixture.path.clone()).signing_message()?);
    assert_eq!(verified.transport_group_id(), <[u8; 32]>::from(Sha256::digest(&group)));
    let second_fixture = PathFixture::new(&second_signer, &second_context)?;
    assert_ne!(verified.transport_group_id(), second_fixture.parts(&second_signer, &second_context)?
        .build(&second_context)?.transport_group_id());
    Ok(())
}

#[test]
fn complete_network_chain_accepts_both_members_and_enforces_signed_route_policy()
    -> Result<(), Box<dyn std::error::Error>> {
    let signer = NetworkAuthoritySigner::from_master_seed(&[42; 32])?;
    let key = signer.public_key();
    let revoked = BTreeSet::new();
    let context = verification_context(&key, &revoked);
    let fixture = PathFixture::new(&signer, &context)?;
    let mut parts = fixture.parts(&signer, &context)?;
    parts.members.swap(0, 1);
    let path = parts.build(&context)?;
    assert_eq!(path.peers(), fixture.path.peers);
    assert_eq!(path.purpose(), Purpose::RemoteControl);
    path.check_route(&context, &[])?;
    path.check_route(&context, &fixture.path.policy.relays)?;
    assert!(path.check_route(&context, &[PeerId::from_public_key(&[21; 32])]).is_err());
    assert!(path.check_route(&context, &[fixture.path.peers.first]).is_err());
    assert!(path.check_route(&context, &[fixture.path.policy.relays[0]; 2]).is_err());
    Ok(())
}

#[test]
fn network_chain_rejects_wrong_grant_kinds_and_missing_or_wrong_members()
    -> Result<(), Box<dyn std::error::Error>> {
    let signer = NetworkAuthoritySigner::from_master_seed(&[42; 32])?;
    let key = signer.public_key();
    let revoked = BTreeSet::new();
    let context = verification_context(&key, &revoked);
    let fixture = PathFixture::new(&signer, &context)?;
    let parts = fixture.parts(&signer, &context)?;
    assert!(VerifiedMembership::from_grant(parts.connection.clone(), &context,
        &fixture.members[0].installation_id, &fixture.members[0].public_key, 3).is_err());
    let mut wrong = parts.clone();
    wrong.connection = wrong.path.clone();
    assert!(wrong.build(&context).is_err());
    let mut wrong = parts.clone();
    wrong.path = wrong.connection.clone();
    assert!(wrong.build(&context).is_err());
    for missing in 0..2 {
        let mut wrong = parts.clone();
        wrong.members[missing] = wrong.members[1 - missing].clone();
        assert!(wrong.build(&context).is_err());
    }
    let mut other = fixture.members[0].clone();
    other.public_key = [30; 32];
    other.peer = PeerId::from_public_key(&other.public_key);
    other.scope.grant_id = grant_scope(30).grant_id;
    let mut wrong = parts;
    wrong.members[0] = bind_member(&signer, &context, &other)?;
    assert!(wrong.build(&context).is_err());
    Ok(())
}

#[test]
fn network_chain_rejects_wrong_references_peers_and_purpose()
    -> Result<(), Box<dyn std::error::Error>> {
    let signer = NetworkAuthoritySigner::from_master_seed(&[42; 32])?;
    let key = signer.public_key();
    let revoked = BTreeSet::new();
    let context = verification_context(&key, &revoked);
    let fixture = PathFixture::new(&signer, &context)?;
    for case in 0..7 {
        let mut wrong = fixture.clone();
        match case {
            0 => wrong.connection.membership_digests[0] = [90; 32],
            1 => wrong.connection.membership_digests.swap(0, 1),
            2 => wrong.connection.business_grant_digest = [91; 32],
            3 => wrong.path.connectivity_grant_digest = [92; 32],
            4 => wrong.path.purpose = Purpose::PrivateService,
            5 => wrong.path.peers = PeerPair::new(wrong.members[0].peer, PeerId::from_public_key(&[31; 32]))?,
            _ => wrong.connection.peers = PeerPair::new(wrong.members[0].peer, PeerId::from_public_key(&[31; 32]))?,
        }
        // Refresh only the outer reference so each inner mismatch is tested,
        // rather than failing earlier on a stale ConnectivityGrant digest.
        if case != 3 {
            wrong.path.connectivity_grant_digest = sign_verify(&signer, &context,
                GrantClaims::Connectivity(wrong.connection.clone()))?.digest();
        }
        assert!(wrong.parts(&signer, &context)?.build(&context).is_err(), "case {case}");
    }
    let parts = fixture.parts(&signer, &context)?;
    assert!(VerifiedNetworkPath::from_grants(&context, parts.members,
        parts.connection, parts.path, [93; 32]).is_err());
    Ok(())
}

#[test]
fn network_chain_rejects_child_lifetime_expansion_even_when_every_grant_is_current()
    -> Result<(), Box<dyn std::error::Error>> {
    let signer = NetworkAuthoritySigner::from_master_seed(&[42; 32])?;
    let key = signer.public_key();
    let revoked = BTreeSet::new();
    let context = verification_context(&key, &revoked);
    let fixture = PathFixture::new(&signer, &context)?;
    for case in 0..8 {
        let mut wrong = fixture.clone();
        match case {
            0 => wrong.connection.scope.not_before_ms = 999,
            1 => wrong.connection.scope.expires_at_ms = 2001,
            2 => wrong.path.scope.not_before_ms = 1099,
            3 => wrong.path.scope.expires_at_ms = 1901,
            4 => wrong.members[0].scope.not_before_ms = 1150,
            5 => wrong.members[0].scope.expires_at_ms = 1850,
            6 => wrong.members[1].scope.not_before_ms = 1150,
            _ => wrong.members[1].scope.expires_at_ms = 1850,
        }
        wrong.refresh_references(&signer, &context)?;
        assert!(matches!(wrong.parts(&signer, &context)?.build(&context),
            Err(error) if error.code == ErrorCode::PermissionRequired), "case {case}");
    }
    Ok(())
}

#[test]
fn every_chain_object_is_rechecked_for_revocation_at_construction_and_before_routes()
    -> Result<(), Box<dyn std::error::Error>> {
    let signer = NetworkAuthoritySigner::from_master_seed(&[42; 32])?;
    let key = signer.public_key();
    let empty = BTreeSet::new();
    let context = verification_context(&key, &empty);
    let fixture = PathFixture::new(&signer, &context)?;
    let parts = fixture.parts(&signer, &context)?;
    let path = parts.clone().build(&context)?;
    for scope in [&fixture.members[0].scope, &fixture.members[1].scope,
        &fixture.connection.scope, &fixture.path.scope] {
        let revoked = BTreeSet::from([scope.grant_id.clone()]);
        let current = NetworkVerification { revoked_grant_ids: &revoked, ..verification_context(&key, &empty) };
        assert!(matches!(parts.clone().build(&current), Err(error) if error.code == ErrorCode::PolicyRevoked));
        assert!(matches!(path.check_current(&current), Err(error) if error.code == ErrorCode::PolicyRevoked));
        assert!(matches!(path.check_route(&current, &[]), Err(error) if error.code == ErrorCode::PolicyRevoked));
    }
    for now_ms in [1199, 1800, 1900, 2000] {
        let current = NetworkVerification { now_ms, ..verification_context(&key, &empty) };
        assert!(matches!(parts.clone().build(&current), Err(error) if error.code == ErrorCode::LeaseExpired));
        assert!(matches!(path.check_route(&current, &[]), Err(error) if error.code == ErrorCode::LeaseExpired));
    }
    Ok(())
}

#[test]
fn network_chain_rejects_mixed_authorities_and_scope_snapshots()
    -> Result<(), Box<dyn std::error::Error>> {
    let signer = NetworkAuthoritySigner::from_master_seed(&[42; 32])?;
    let other_signer = NetworkAuthoritySigner::from_master_seed(&[43; 32])?;
    let key = signer.public_key();
    let other_key = other_signer.public_key();
    let revoked = BTreeSet::new();
    let context = verification_context(&key, &revoked);
    let fixture = PathFixture::new(&signer, &context)?;
    let parts = fixture.parts(&signer, &context)?;
    let other_context = NetworkVerification { authority_key: &other_key, ..verification_context(&key, &revoked) };
    for slot in 0..4 {
        let mut wrong = parts.clone();
        match slot {
            0 | 1 => wrong.members[slot] = bind_member(&other_signer, &other_context, &fixture.members[slot])?,
            2 => wrong.connection = sign_verify(&other_signer, &other_context, GrantClaims::Connectivity(fixture.connection.clone()))?,
            _ => wrong.path = sign_verify(&other_signer, &other_context, GrantClaims::Path(fixture.path.clone()))?,
        }
        assert!(matches!(wrong.build(&context), Err(error) if error.code == ErrorCode::IdentityMismatch));
    }
    for case in 0..3 {
        let mut scope = fixture.members[0].clone();
        let mut foreign = verification_context(&key, &revoked);
        match case {
            0 => {
                foreign.space_id = "20000000-0000-4000-8000-000000000003";
                scope.scope.space_id = foreign.space_id.into();
            }
            1 => {
                foreign.deployment_id = "10000000-0000-4000-8000-000000000003";
                scope.scope.deployment_id = foreign.deployment_id.into();
            }
            _ => { foreign.policy_epoch = 8; scope.scope.policy_epoch = 8; }
        }
        let mut wrong = parts.clone();
        wrong.members[0] = bind_member(&signer, &foreign, &scope)?;
        assert!(wrong.build(&context).is_err());
    }
    let path = parts.build(&context)?;
    assert!(path.check_current(&other_context).is_err());
    let replaced_policy = NetworkVerification { policy_epoch: 8, ..verification_context(&key, &revoked) };
    assert!(matches!(path.check_current(&replaced_policy), Err(error) if error.code == ErrorCode::PolicyRevoked));
    Ok(())
}

#[test]
fn signature_context_expiry_revocation_and_rechecks_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = NetworkAuthoritySigner::from_master_seed(&[42; 32])?;
    let key = signer.public_key();
    let revoked = BTreeSet::new();
    let mut context = NetworkVerification {
        authority_key: &key, deployment_id: "10000000-0000-4000-8000-000000000001",
        space_id: "20000000-0000-4000-8000-000000000002", policy_epoch: 7, now_ms: 1500,
        revoked_grant_ids: &revoked,
    };
    let signed = signer.sign(&membership())?;
    let verified = verify_network_grant(&signed, &context)?;
    context.now_ms = 2000;
    assert!(matches!(verified.check_current(&context), Err(e) if e.code == ErrorCode::LeaseExpired));
    context.now_ms = 999;
    assert!(verify_network_grant(&signed, &context).is_err());
    context.now_ms = 1500;
    context.policy_epoch = 8;
    assert!(matches!(verified.check_current(&context), Err(e) if e.code == ErrorCode::PolicyRevoked));
    context.policy_epoch = 7;
    context.space_id = "20000000-0000-4000-8000-000000000005";
    assert!(verify_network_grant(&signed, &context).is_err());
    context.space_id = "20000000-0000-4000-8000-000000000002";
    let revoked = BTreeSet::from([membership().scope().grant_id.clone()]);
    context.revoked_grant_ids = &revoked;
    assert!(matches!(verified.check_current(&context), Err(e) if e.code == ErrorCode::PolicyRevoked));
    let empty_revocations = BTreeSet::new();
    context.revoked_grant_ids = &empty_revocations;
    let mut tampered = signed;
    tampered.signature[0] ^= 1;
    assert!(verify_network_grant(&tampered, &context).is_err());
    Ok(())
}

#[test]
fn network_key_is_distinct_from_legacy_permit_and_node_policy_keys()
-> Result<(), Box<dyn std::error::Error>> {
    let seed = [42; 32];
    let network = NetworkAuthoritySigner::from_master_seed(&seed)?;
    let legacy = nestlink_identity::PermitSigner::from_seed(seed);
    assert_ne!(network.public_key(), legacy.public_key());
    assert_ne!(network.public_key(), legacy.node_policy_signer()?.public_key());
    let signed = network.sign(&membership())?;
    let revoked = BTreeSet::new();
    let legacy_key = legacy.public_key();
    let context = NetworkVerification {
        authority_key: &legacy_key, deployment_id: "10000000-0000-4000-8000-000000000001",
        space_id: "20000000-0000-4000-8000-000000000002", policy_epoch: 7, now_ms: 1500,
        revoked_grant_ids: &revoked,
    };
    assert!(verify_network_grant(&signed, &context).is_err());
    Ok(())
}
