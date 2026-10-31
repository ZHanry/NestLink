use nestlink_protocol::{network::GrantScope, network_topology::BootIncarnation, wireguard::*};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn claims() -> Result<WireGuardClientBindingClaims> {
    let id = |suffix| format!("00000000-0000-4000-8000-{suffix:012}");
    Ok(WireGuardClientBindingClaims {
        binding_version: WIREGUARD_BINDING_VERSION,
        scope: GrantScope {
            schema_version: 1,
            deployment_id: id(1),
            space_id: id(2),
            grant_id: id(3),
            policy_epoch: 1,
            not_before_ms: 1000,
            expires_at_ms: 5000,
        },
        client_id: id(4),
        client_revision: 1,
        account_id: id(5),
        installation_id: id(6),
        client_public_key: [13; 32],
        client_address: "10.210.7.2".parse()?,
        portal_node_id: id(7),
        portal_public_key: [14; 32],
        portal_incarnation: BootIncarnation {
            runtime_generation: 1,
            runtime_id: id(8),
        },
        access_grant_id: id(9),
        access_digest: [15; 32],
        committed_bytes: 1024,
    })
}
#[test]
fn canonical_binding_rejects_ambiguous_key_address_budget_and_extension_fields() -> Result {
    let original = claims()?;
    let bytes = original.canonical_bytes()?;
    assert_eq!(
        WireGuardClientBindingClaims::decode_canonical(&bytes)?,
        original
    );
    let mut whitespace = bytes.clone();
    whitespace.push(b' ');
    assert!(WireGuardClientBindingClaims::decode_canonical(&whitespace).is_err());
    let mut extended = serde_json::to_value(&original)?;
    extended["allow_portal_acl"] = serde_json::json!(true);
    assert!(
        WireGuardClientBindingClaims::decode_canonical(&serde_json::to_vec(&extended)?).is_err()
    );
    for fault in 0..9 {
        let mut changed = original.clone();
        match fault {
            0 => changed.binding_version += 1,
            1 => changed.client_public_key = [0; 32],
            2 => changed.portal_public_key = [0; 32],
            3 => changed.client_address = "8.8.8.8".parse()?,
            4 => changed.client_address = "10.210.7.0".parse()?,
            5 => changed.client_address = "10.210.7.255".parse()?,
            6 => changed.committed_bytes = 0,
            7 => changed.client_revision = 0,
            8 => changed.scope.grant_id = changed.access_grant_id.clone(),
            _ => unreachable!(),
        }
        assert!(changed.validate().is_err());
    }
    assert!(
        SignedWireGuardClientBinding {
            claims: bytes.clone(),
            signature: vec![0; 63]
        }
        .validate()
        .is_err()
    );
    assert!(
        SignedWireGuardClientBinding {
            claims: vec![0; WIREGUARD_BINDING_BYTES + 1],
            signature: vec![0; 64]
        }
        .validate()
        .is_err()
    );
    Ok(())
}
