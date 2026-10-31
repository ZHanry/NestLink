use super::*;
use nestlink_identity::{
    network::{NetworkAuthoritySigner, NetworkVerification, verify_network_grant},
    wireguard::{WireGuardPortalState, verify_wireguard_client_binding},
};
use nestlink_protocol::{
    network::{
        Direction, GrantScope, IpPrefix, IpProtocol, NetworkAccessClaims, NetworkRule, PeerId,
    },
    network_topology::BootIncarnation,
    wireguard::WireGuardClientBindingClaims,
};
use std::{
    collections::BTreeSet,
    time::{SystemTime, UNIX_EPOCH},
};

fn binding(
    destination: IpPrefix,
) -> Result<nestlink_identity::wireguard::VerifiedWireGuardClientBinding> {
    let id = |value| format!("00000000-0000-4000-8000-{value:012}");
    let now: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?;
    let signer = NetworkAuthoritySigner::from_master_seed(&[21; 32])?;
    let key = signer.public_key();
    let revoked = BTreeSet::new();
    let deployment = id(1);
    let space = id(2);
    let context = NetworkVerification {
        authority_key: &key,
        deployment_id: &deployment,
        space_id: &space,
        policy_epoch: 1,
        now_ms: now,
        revoked_grant_ids: &revoked,
    };
    let scope = GrantScope {
        schema_version: 1,
        deployment_id: deployment.clone(),
        space_id: space.clone(),
        grant_id: id(3),
        policy_epoch: 1,
        not_before_ms: now,
        expires_at_ms: now + 60_000,
    };
    let original = signer.sign(&GrantClaims::NetworkAccess(NetworkAccessClaims {
        scope: scope.clone(),
        source: PeerId::from_public_key(&[22; 32]),
        destination: PeerId::from_public_key(&[23; 32]),
        source_prefixes: vec![IpPrefix {
            network: "10.210.7.2".parse()?,
            prefix_len: 32,
        }],
        destination_prefixes: vec![destination],
        rules: vec![NetworkRule {
            protocol: IpProtocol::Udp,
            direction: Direction::Inbound,
            ports: Some([53, 53]),
        }],
        byte_limit: 8192,
    }))?;
    let original = verify_network_grant(&original, &context)?;
    let mut binding_scope = scope;
    binding_scope.grant_id = id(4);
    let claims = WireGuardClientBindingClaims {
        binding_version: 1,
        scope: binding_scope,
        client_id: id(5),
        client_revision: 1,
        account_id: id(6),
        installation_id: id(7),
        client_public_key: [24; 32],
        client_address: "10.210.7.2".parse()?,
        portal_node_id: id(8),
        portal_public_key: [22; 32],
        portal_incarnation: BootIncarnation {
            runtime_id: id(9),
            runtime_generation: 1,
        },
        access_grant_id: id(3),
        access_digest: original.digest(),
        committed_bytes: 8192,
    };
    let portal = WireGuardPortalState {
        node_id: &claims.portal_node_id,
        public_key: &claims.portal_public_key,
        incarnation: &claims.portal_incarnation,
        lease_expires_at_ms: now + 10_000,
        client_revision: 1,
    };
    Ok(verify_wireguard_client_binding(
        &signer.sign_wireguard_client_binding(&claims)?,
        &context,
        original,
        &portal,
    )?)
}
#[test]
fn standard_config_uses_only_original_client_address_and_approved_destinations() -> Result {
    let binding = binding(IpPrefix {
        network: "10.211.0.0".parse()?,
        prefix_len: 24,
    })?;
    let secret = [25; 32];
    let server = [26; 32];
    let exported = configuration(&binding, &secret, server, "198.18.0.10:51820".parse()?)?;
    assert!(exported.contains("Address = 10.210.7.2/32\n"));
    assert!(exported.contains("AllowedIPs = 10.211.0.0/24\n"));
    assert!(exported.contains(&format!("PrivateKey = {}\n", STANDARD.encode(secret))));
    assert!(exported.contains(&format!("PublicKey = {}\n", STANDARD.encode(server))));
    for unwanted in ["0.0.0.0/0", "::/0", "PostUp", "PostDown", "DNS ="] {
        assert!(!exported.contains(unwanted));
    }
    assert!(configuration(&binding, &secret, server, "10.211.0.10:51820".parse()?).is_err());
    assert!(configuration(&binding, &secret, server, "0.0.0.0:51820".parse()?).is_err());
    assert!(configuration(&binding, &secret, server, "198.18.0.10:0".parse()?).is_err());
    assert!(configuration(&binding, &secret, [0; 32], "198.18.0.10:51820".parse()?).is_err());
    Ok(())
}
#[test]
fn private_exports_refuse_existing_files_shared_directories_and_noncanonical_keys() -> Result {
    let directory = tempfile::tempdir()?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    let path = directory.path().join("client.conf");
    save(&path, b"test-only-private-config")?;
    assert!(save(&path, b"replacement").is_err());
    assert_eq!(
        &*nestlink_platform_security::read_private(&path, 128)?,
        b"test-only-private-config"
    );
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755))?;
    assert!(save(&directory.path().join("qr.svg"), b"test-only-private-qr").is_err());
    assert!(key(&STANDARD.encode([0; 32])).is_err());
    assert!(key(&format!("{}\n", STANDARD.encode([1; 32]))).is_err());
    assert!(key(&STANDARD.encode([1; 31])).is_err());
    assert!(digest(&STANDARD.encode([1; 32])).is_err());
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    directory.close()?;
    Ok(())
}
#[tokio::test]
#[ignore = "dedicated GitHub-hosted WireGuard workflow installs reviewed wg/qrencode tools"]
async fn distribution_wireguard_derives_independent_keys_and_qrencode_exports_bounded_svg() -> Result
{
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || std::env::var("RUNNER_ENVIRONMENT").as_deref() != Ok("github-hosted")
    {
        return Err(
            io::Error::other("R02: dedicated GitHub-hosted WireGuard workflow required").into(),
        );
    }
    let first = tools::run("wg", &["genkey"], &[], 128).await?;
    let second = tools::run("wg", &["genkey"], &[], 128).await?;
    let first = Zeroizing::new(key(std::str::from_utf8(&first)?.trim_end_matches('\n'))?);
    let second = Zeroizing::new(key(std::str::from_utf8(&second)?.trim_end_matches('\n'))?);
    let first_public = public_key_for(&first).await?;
    assert_ne!(first_public, public_key_for(&second).await?);
    let binding = binding(IpPrefix {
        network: "10.211.0.0".parse()?,
        prefix_len: 24,
    })?;
    let config = configuration(&binding, &first, [26; 32], "198.18.0.10:51820".parse()?)?;
    let qr = tools::run(
        "qrencode",
        &["-t", "SVG", "-l", "M", "-o", "-"],
        config.as_bytes(),
        1_048_576,
    )
    .await?;
    assert!(std::str::from_utf8(&qr)?.contains("<svg"));
    assert!(!qr.is_empty());
    Ok(())
}
