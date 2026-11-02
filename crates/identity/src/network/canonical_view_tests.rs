//! The view adapter must retain every original envelope and live check.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_protocol::{api::NetworkGrantView, network::SpaceRole};

fn membership() -> GrantClaims {
    let public_key = [9; 32];
    GrantClaims::Membership(MembershipClaims {
        scope: GrantScope {
            schema_version: 1,
            deployment_id: "10000000-0000-4000-8000-000000000001".into(),
            space_id: "20000000-0000-4000-8000-000000000002".into(),
            grant_id: "30000000-0000-4000-8000-000000000003".into(),
            policy_epoch: 7,
            not_before_ms: 1000,
            expires_at_ms: 2000,
        },
        installation_id: "40000000-0000-4000-8000-000000000004".into(),
        peer: PeerId::from_public_key(&public_key),
        public_key,
        membership_epoch: 3,
        role: SpaceRole::Member,
    })
}

fn view(signed: &SignedNetworkGrant, grant_id: &str) -> NetworkGrantView {
    NetworkGrantView {
        schema_version: 1,
        grant_id: grant_id.into(),
        claims: URL_SAFE_NO_PAD.encode(&signed.claims),
        signature: URL_SAFE_NO_PAD.encode(&signed.signature),
    }
}

#[test]
fn private_network_view_reuse_preserves_original_canonical_and_live_checks()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = NetworkAuthoritySigner::from_master_seed(&[42; 32])?;
    let key = signer.public_key();
    let claims = membership();
    let scope = claims.scope();
    let signed = signer.sign(&claims)?;
    let envelope = view(&signed, &scope.grant_id);
    let empty_revocations = BTreeSet::new();
    let revoked = BTreeSet::from([scope.grant_id.clone()]);
    let foreign_key = NetworkAuthoritySigner::from_master_seed(&[43; 32])?.public_key();
    let mut context = NetworkVerification {
        authority_key: &key,
        deployment_id: &scope.deployment_id,
        space_id: &scope.space_id,
        policy_epoch: scope.policy_epoch,
        now_ms: 1500,
        revoked_grant_ids: &empty_revocations,
    };
    let original = verify_network_grant(&signed, &context)?;
    let verified = remote::verify_view(&envelope, &context)?;
    assert_eq!(verified.claims(), original.claims());
    assert_eq!(verified.digest(), original.digest());
    assert_eq!(verified.issuer(), original.issuer());
    let standalone = remote::signed(&envelope)?;
    assert_eq!(standalone.claims, signed.claims);
    assert_eq!(standalone.signature, signed.signature);

    // Even a correctly signed noncanonical JSON transcript stays invalid.
    let mut noncanonical = signed.clone();
    noncanonical.claims.insert(0, b' ');
    let mut message = claims.domain().to_vec();
    message.extend_from_slice(&u32::try_from(noncanonical.claims.len())?.to_be_bytes());
    message.extend_from_slice(&noncanonical.claims);
    noncanonical.signature = signer.key.sign(&message).to_bytes().to_vec();
    assert!(verify_network_grant(&noncanonical, &context).is_err());
    let noncanonical = view(&noncanonical, &scope.grant_id);
    assert!(remote::signed(&noncanonical).is_err());
    assert!(remote::verify_view(&noncanonical, &context).is_err());
    for case in 0..4 {
        let mut changed = envelope.clone();
        match case {
            0 => changed.claims.push('='),
            1 => changed.signature.push('='),
            2 => changed.claims.push('+'),
            _ => changed.signature.push('/'),
        }
        assert!(remote::signed(&changed).is_err());
        assert!(remote::verify_view(&changed, &context).is_err());
    }

    let mut corrupt = signed.clone();
    corrupt.signature[0] ^= 1;
    let corrupt = view(&corrupt, &scope.grant_id);
    assert!(
        matches!(remote::verify_view(&corrupt, &context), Err(error) if error.code == ErrorCode::IdentityMismatch)
    );
    // Invalid metadata still wins before an otherwise invalid signature.
    for case in 0..2 {
        let mut changed = corrupt.clone();
        if case == 0 {
            changed.schema_version = 2;
        } else {
            changed.grant_id = "30000000-0000-4000-8000-000000000005".into();
        }
        assert!(
            matches!(remote::verify_view(&changed, &context), Err(error) if error.code == ErrorCode::PermissionRequired)
        );
    }
    context.authority_key = &foreign_key;
    assert!(
        matches!(remote::verify_view(&envelope, &context), Err(error) if error.code == ErrorCode::IdentityMismatch)
    );
    context.authority_key = &key;
    for at in [999, 2000] {
        context.now_ms = at;
        assert!(
            matches!(remote::verify_view(&envelope, &context), Err(error) if error.code == ErrorCode::LeaseExpired)
        );
        assert!(verified.check_current(&context).is_err());
    }
    context.now_ms = 1500;
    context.policy_epoch += 1;
    assert!(
        matches!(remote::verify_view(&envelope, &context), Err(error) if error.code == ErrorCode::PolicyRevoked)
    );
    context.policy_epoch = scope.policy_epoch;
    context.revoked_grant_ids = &revoked;
    assert!(
        matches!(remote::verify_view(&envelope, &context), Err(error) if error.code == ErrorCode::PolicyRevoked)
    );
    assert!(verified.check_current(&context).is_err());
    context.revoked_grant_ids = &empty_revocations;
    assert_eq!(
        remote::verify_view(&envelope, &context)?.digest(),
        original.digest()
    );
    Ok(())
}
