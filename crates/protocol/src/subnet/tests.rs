use super::*;

fn claims() -> Result<SubnetMappingClaims, Box<dyn std::error::Error>> {
    Ok(SubnetMappingClaims {
        mapping_version: SUBNET_MAPPING_VERSION,
        scope: GrantScope { schema_version: 1, deployment_id: "00000000-0000-4000-8000-000000000001".into(),
            space_id: "00000000-0000-4000-8000-000000000002".into(), grant_id: "00000000-0000-4000-8000-000000000003".into(),
            policy_epoch: 1, not_before_ms: 1000, expires_at_ms: 61_000 },
        gateway_node_id: "00000000-0000-4000-8000-000000000004".into(), gateway_public_key: [7; 32], gateway: PeerId::from_public_key(&[7; 32]),
        gateway_incarnation: BootIncarnation { runtime_generation: 1, runtime_id: "00000000-0000-4000-8000-000000000005".into() },
        original: IpPrefix { network: "192.168.1.0".parse()?, prefix_len: 24 },
        alias: IpPrefix { network: "10.210.1.0".parse()?, prefix_len: 24 },
        route_export_digest: [8; 32], mapping_revision: 1,
    })
}
#[test]
fn mapping_canonical_roundtrip_and_strict_schema() -> Result<(), Box<dyn std::error::Error>> {
    let claims = claims()?;
    let bytes = claims.canonical_bytes()?;
    assert_eq!(SubnetMappingClaims::decode_canonical(&bytes)?, claims);
    let mut spaced = bytes.clone();
    spaced.push(b' ');
    assert!(SubnetMappingClaims::decode_canonical(&spaced).is_err());
    assert!(SubnetMappingClaims::decode_canonical(&vec![b' '; SUBNET_MAPPING_BYTES + 1]).is_err());
    let mut extra = serde_json::to_value(&claims)?;
    extra["command"] = serde_json::json!(["route", "replace", "default"]);
    assert!(serde_json::from_value::<SubnetMappingClaims>(extra).is_err());
    for fault in 0..10 {
        let mut changed = claims.clone();
        match fault {
            0 => changed.mapping_version += 1,
            1 => changed.original.network = "192.168.1.4".parse()?,
            2 => changed.original.prefix_len = 0,
            3 => changed.alias.prefix_len = 25,
            4 => changed.gateway_public_key[0] ^= 1,
            5 => changed.gateway_incarnation.runtime_generation = 0,
            6 => changed.mapping_revision = 0,
            7 => changed.route_export_digest = [0; 32],
            8 => changed.scope.expires_at_ms = changed.scope.not_before_ms + MAX_SUBNET_MAPPING_MS + 1,
            9 => changed.alias.network = "fd81::".parse()?,
            _ => unreachable!(),
        }
        assert!(changed.validate().is_err(), "mapping fault {fault}");
    }
    Ok(())
}
#[test]
fn ipv6_routing_is_explicit_and_translation_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let mut claims = claims()?;
    claims.original = IpPrefix { network: "fd81:1::".parse()?, prefix_len: 64 };
    claims.alias = claims.original;
    claims.validate()?;
    claims.alias.network = "fd81:2::".parse()?;
    assert!(claims.validate().is_err());
    claims.original = IpPrefix { network: "192.168.1.1".parse()?, prefix_len: 32 };
    claims.alias = IpPrefix { network: "10.210.1.1".parse()?, prefix_len: 32 };
    claims.validate()?;
    Ok(())
}
