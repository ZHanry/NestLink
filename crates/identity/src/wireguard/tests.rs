use super::*;
use crate::network::{SignedNetworkGrant, verify_network_grant};
use nestlink_protocol::{
    network::{Direction, GrantScope, IpProtocol, NetworkAccessClaims, NetworkRule},
    wireguard::WIREGUARD_BINDING_VERSION,
};
use std::collections::BTreeSet;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const DEPLOYMENT: &str = "00000000-0000-4000-8000-000000000001";
const SPACE: &str = "00000000-0000-4000-8000-000000000002";
fn context<'a>(key: &'a [u8; 32], revoked: &'a BTreeSet<String>) -> NetworkVerification<'a> {
    NetworkVerification {
        authority_key: key,
        deployment_id: DEPLOYMENT,
        space_id: SPACE,
        policy_epoch: 3,
        now_ms: 2000,
        revoked_grant_ids: revoked,
    }
}
fn portal(claims: &WireGuardClientBindingClaims) -> WireGuardPortalState<'_> {
    WireGuardPortalState {
        node_id: &claims.portal_node_id,
        public_key: &claims.portal_public_key,
        incarnation: &claims.portal_incarnation,
        lease_expires_at_ms: 5000,
        client_revision: claims.client_revision,
    }
}
fn fixture() -> Result<(
    NetworkAuthoritySigner,
    WireGuardClientBindingClaims,
    VerifiedNetworkGrant,
)> {
    let signer = NetworkAuthoritySigner::from_master_seed(&[34; 32])?;
    let scope = GrantScope {
        schema_version: 1,
        deployment_id: DEPLOYMENT.into(),
        space_id: SPACE.into(),
        grant_id: "00000000-0000-4000-8000-000000000003".into(),
        policy_epoch: 3,
        not_before_ms: 1000,
        expires_at_ms: 6000,
    };
    let original = signer.sign(&GrantClaims::NetworkAccess(NetworkAccessClaims {
        scope: scope.clone(),
        source: PeerId::from_public_key(&[11; 32]),
        destination: PeerId::from_public_key(&[12; 32]),
        source_prefixes: vec![IpPrefix {
            network: "10.210.7.2".parse()?,
            prefix_len: 32,
        }],
        destination_prefixes: vec![IpPrefix {
            network: "192.168.15.0".parse()?,
            prefix_len: 24,
        }],
        rules: vec![NetworkRule {
            protocol: IpProtocol::Tcp,
            direction: Direction::Inbound,
            ports: Some([443, 443]),
        }],
        byte_limit: 8192,
    }))?;
    let key = signer.public_key();
    let empty = BTreeSet::new();
    let original = verify_network_grant(&original, &context(&key, &empty))?;
    let mut scope = scope;
    scope.grant_id = "00000000-0000-4000-8000-000000000004".into();
    let claims = WireGuardClientBindingClaims {
        binding_version: WIREGUARD_BINDING_VERSION,
        scope,
        client_id: "00000000-0000-4000-8000-000000000005".into(),
        client_revision: 1,
        account_id: "00000000-0000-4000-8000-000000000006".into(),
        installation_id: "00000000-0000-4000-8000-000000000007".into(),
        client_public_key: [21; 32],
        client_address: "10.210.7.2".parse()?,
        portal_node_id: "00000000-0000-4000-8000-000000000008".into(),
        portal_public_key: [11; 32],
        portal_incarnation: BootIncarnation {
            runtime_generation: 1,
            runtime_id: "00000000-0000-4000-8000-000000000009".into(),
        },
        access_grant_id: original.claims().scope().grant_id.clone(),
        access_digest: original.digest(),
        committed_bytes: 8192,
    };
    Ok((signer, claims, original))
}
#[test]
fn independent_wireguard_key_binding_cannot_replace_or_expand_original_packet_business() -> Result {
    let (signer, claims, access) = fixture()?;
    let key = signer.public_key();
    let empty = BTreeSet::new();
    let context = context(&key, &empty);
    let signed = signer.sign_wireguard_client_binding(&claims)?;
    let verified =
        verify_wireguard_client_binding(&signed, &context, access.clone(), &portal(&claims))?;
    assert_eq!(verified.claims(), &claims);
    assert_eq!(verified.effective_expires_at_ms(&portal(&claims)), 5000);
    assert!(
        verify_network_grant(
            &SignedNetworkGrant {
                claims: signed.claims.clone(),
                signature: signed.signature.clone()
            },
            &context
        )
        .is_err()
    );
    let mut old_purpose = signed.clone();
    old_purpose.signature = signer.sign(access.claims())?.signature;
    assert!(
        verify_wireguard_client_binding(&old_purpose, &context, access.clone(), &portal(&claims))
            .is_err()
    );
    for fault in 0..5 {
        let mut changed = claims.clone();
        match fault {
            0 => changed.client_address = "10.210.7.3".parse()?,
            1 => changed.committed_bytes -= 1,
            2 => changed.access_digest[0] ^= 1,
            3 => changed.scope.expires_at_ms += 1,
            4 => changed.portal_public_key = [17; 32],
            _ => unreachable!(),
        }
        let signed = signer.sign_wireguard_client_binding(&changed)?;
        assert!(
            verify_wireguard_client_binding(&signed, &context, access.clone(), &portal(&claims))
                .is_err()
        );
    }
    let mut tampered = signed;
    let mut altered = claims.clone();
    altered.client_public_key = [22; 32];
    tampered.claims = altered.canonical_bytes()?;
    assert!(
        verify_wireguard_client_binding(&tampered, &context, access, &portal(&claims)).is_err()
    );
    Ok(())
}
#[test]
fn client_rotation_portal_restart_epoch_revocation_and_lease_expiry_stop_original_binding() -> Result
{
    let (signer, claims, access) = fixture()?;
    let key = signer.public_key();
    let empty = BTreeSet::new();
    let current = context(&key, &empty);
    let verified = verify_wireguard_client_binding(
        &signer.sign_wireguard_client_binding(&claims)?,
        &current,
        access,
        &portal(&claims),
    )?;
    let mut changed_boot = claims.portal_incarnation.clone();
    changed_boot.runtime_generation += 1;
    let mut node = portal(&claims);
    node.incarnation = &changed_boot;
    assert!(verified.check_current(&current, &node).is_err());
    node = portal(&claims);
    node.client_revision += 1;
    assert!(verified.check_current(&current, &node).is_err());
    node = portal(&claims);
    node.lease_expires_at_ms = current.now_ms;
    assert!(verified.check_current(&current, &node).is_err());
    let mut epoch = context(&key, &empty);
    epoch.policy_epoch += 1;
    assert!(verified.check_current(&epoch, &portal(&claims)).is_err());
    for id in [&claims.scope.grant_id, &claims.access_grant_id] {
        let revoked = BTreeSet::from([id.clone()]);
        assert!(
            verified
                .check_current(&context(&key, &revoked), &portal(&claims))
                .is_err()
        );
    }
    let mut expired = context(&key, &empty);
    expired.now_ms = claims.scope.expires_at_ms;
    assert!(verified.check_current(&expired, &portal(&claims)).is_err());
    Ok(())
}
