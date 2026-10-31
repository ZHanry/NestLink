use super::*;
use crate::network::{SignedNetworkGrant, verify_network_grant};
use nestlink_protocol::{network::{GrantScope, IpPrefix, PeerId, RouteExportClaims}, subnet::SUBNET_MAPPING_VERSION};
use std::collections::BTreeSet;

const DEPLOYMENT: &str = "00000000-0000-4000-8000-000000000001";
const SPACE: &str = "00000000-0000-4000-8000-000000000002";
fn context<'a>(key: &'a [u8; 32], revoked: &'a BTreeSet<String>) -> NetworkVerification<'a> {
    NetworkVerification { authority_key: key, deployment_id: DEPLOYMENT, space_id: SPACE, policy_epoch: 3, now_ms: 2000, revoked_grant_ids: revoked }
}
fn gateway(claims: &SubnetMappingClaims) -> SubnetGatewayState<'_> {
    SubnetGatewayState { node_id: &claims.gateway_node_id, public_key: &claims.gateway_public_key,
        incarnation: &claims.gateway_incarnation, mapping_revision: claims.mapping_revision, lease_expires_at_ms: 50_000 }
}
fn fixture() -> Result<(NetworkAuthoritySigner, SubnetMappingClaims, VerifiedNetworkGrant), Box<dyn std::error::Error>> {
    let signer = NetworkAuthoritySigner::from_master_seed(&[11; 32])?;
    let scope = GrantScope { schema_version: 1, deployment_id: DEPLOYMENT.into(), space_id: SPACE.into(),
        grant_id: "00000000-0000-4000-8000-000000000003".into(), policy_epoch: 3, not_before_ms: 1000, expires_at_ms: 61_000 };
    let original = IpPrefix { network: "192.168.1.0".parse()?, prefix_len: 24 };
    let alias = IpPrefix { network: "10.210.1.0".parse()?, prefix_len: 24 };
    let export = signer.sign(&GrantClaims::RouteExport(RouteExportClaims { scope: scope.clone(), gateway: PeerId::from_public_key(&[7; 32]), prefixes: vec![alias, original] }))?;
    let key = signer.public_key();
    let revoked = BTreeSet::new();
    let export = verify_network_grant(&export, &context(&key, &revoked))?;
    let mut scope = scope;
    scope.grant_id = "00000000-0000-4000-8000-000000000004".into();
    let claims = SubnetMappingClaims { mapping_version: SUBNET_MAPPING_VERSION, scope,
        gateway_node_id: "00000000-0000-4000-8000-000000000005".into(), gateway_public_key: [7; 32], gateway: PeerId::from_public_key(&[7; 32]),
        gateway_incarnation: BootIncarnation { runtime_generation: 1, runtime_id: "00000000-0000-4000-8000-000000000006".into() },
        original, alias, route_export_digest: export.digest(), mapping_revision: 2 };
    Ok((signer, claims, export))
}
#[test]
fn exact_mapping_verifies_and_cannot_replace_publication_or_business_purpose() -> Result<(), Box<dyn std::error::Error>> {
    let (signer, claims, export) = fixture()?;
    let key = signer.public_key();
    let revoked = BTreeSet::new();
    let context = context(&key, &revoked);
    let signed = signer.sign_subnet_mapping(&claims)?;
    let mapping = verify_subnet_mapping(&signed, &context, export.clone(), &gateway(&claims))?;
    assert_eq!(mapping.claims(), &claims);
    assert_eq!(mapping.effective_expires_at_ms(&gateway(&claims)), 50_000);
    assert_eq!(verify_subnet_mapping(&signed, &context, export.clone(), &gateway(&claims))?.digest(), mapping.digest());
    assert!(verify_network_grant(&SignedNetworkGrant { claims: signed.claims.clone(), signature: signed.signature.clone() }, &context).is_err());
    let mut wrong_purpose = signed.clone();
    wrong_purpose.signature = signer.sign(export.claims())?.signature;
    assert!(verify_subnet_mapping(&wrong_purpose, &context, export.clone(), &gateway(&claims)).is_err());
    for fault in 0..4 {
        let mut changed = claims.clone();
        match fault {
            0 => changed.original.network = "192.168.2.0".parse()?,
            1 => changed.alias.network = "10.210.2.0".parse()?,
            2 => changed.mapping_revision += 1,
            3 => changed.route_export_digest[0] ^= 1,
            _ => unreachable!(),
        }
        let changed = SignedSubnetMapping { claims: changed.canonical_bytes()?, signature: signed.signature.clone() };
        assert!(verify_subnet_mapping(&changed, &context, export.clone(), &gateway(&claims)).is_err());
    }
    Ok(())
}
#[test]
fn mapping_rechecks_original_node_boot_revision_export_and_live_revocation() -> Result<(), Box<dyn std::error::Error>> {
    let (signer, claims, export) = fixture()?;
    let key = signer.public_key();
    let empty = BTreeSet::new();
    let context = context(&key, &empty);
    let mapping = verify_subnet_mapping(&signer.sign_subnet_mapping(&claims)?, &context, export.clone(), &gateway(&claims))?;
    let mut changed_boot = claims.gateway_incarnation.clone();
    changed_boot.runtime_generation += 1;
    let mut current = gateway(&claims);
    current.incarnation = &changed_boot;
    assert!(mapping.check_current(&context, &current).is_err());
    current = gateway(&claims);
    current.mapping_revision += 1;
    assert!(mapping.check_current(&context, &current).is_err());
    current = gateway(&claims);
    current.lease_expires_at_ms = context.now_ms;
    assert!(mapping.check_current(&context, &current).is_err());
    for id in [&claims.scope.grant_id, &export.claims().scope().grant_id] {
        let revoked = BTreeSet::from([id.clone()]);
        let mut revoked_context = NetworkVerification { revoked_grant_ids: &revoked, ..context };
        assert!(mapping.check_current(&revoked_context, &gateway(&claims)).is_err());
        revoked_context.policy_epoch += 1;
        assert!(mapping.check_current(&revoked_context, &gateway(&claims)).is_err());
    }
    let mut wrong_space = NetworkVerification { space_id: DEPLOYMENT, ..context };
    assert!(mapping.check_current(&wrong_space, &gateway(&claims)).is_err());
    wrong_space.space_id = SPACE;
    wrong_space.now_ms = claims.scope.expires_at_ms;
    assert!(mapping.check_current(&wrong_space, &gateway(&claims)).is_err());
    let mut changed = claims.clone();
    changed.alias.network = "10.211.1.0".parse()?;
    assert!(verify_subnet_mapping(&signer.sign_subnet_mapping(&changed)?, &context, export, &gateway(&changed)).is_err(), "authority signature cannot widen an unrelated exact export");
    Ok(())
}
