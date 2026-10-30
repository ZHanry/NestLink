use nestlink_protocol::network::*;

#[test]
fn negotiation_is_bilateral_and_unknown_required_capabilities_cannot_downgrade()
-> Result<(), Box<dyn std::error::Error>> {
    let legacy = CapabilityOffer {
        schema_version: 1,
        supported: vec![],
        required: vec![],
    };
    let modern = CapabilityOffer {
        schema_version: 1,
        supported: vec![CORE_CAPABILITY.into(), MIGRATION_CAPABILITY.into()],
        required: vec![],
    };
    assert_eq!(negotiate(&legacy, &modern)?, NegotiatedProtocol::LegacyV15);
    assert_eq!(
        negotiate(&modern, &modern)?,
        NegotiatedProtocol::NetworkV1 {
            path_migration: true
        }
    );
    let core_only = CapabilityOffer {
        schema_version: 1,
        supported: vec![CORE_CAPABILITY.into()],
        required: vec![],
    };
    assert_eq!(
        negotiate(&modern, &core_only)?,
        NegotiatedProtocol::NetworkV1 {
            path_migration: false
        }
    );
    let required = CapabilityOffer {
        required: vec![CORE_CAPABILITY.into()],
        ..modern.clone()
    };
    assert!(negotiate(&required, &legacy).is_err());
    let future = CapabilityOffer {
        schema_version: 1,
        supported: vec!["future-auth-v2".into()],
        required: vec!["future-auth-v2".into()],
    };
    assert!(negotiate(&future, &future).is_err());
    let unknown_optional = CapabilityOffer {
        required: vec![],
        ..future
    };
    assert_eq!(
        negotiate(&unknown_optional, &legacy)?,
        NegotiatedProtocol::LegacyV15
    );
    let migration_alone = CapabilityOffer {
        schema_version: 1,
        supported: vec![MIGRATION_CAPABILITY.into()],
        required: vec![],
    };
    assert!(negotiate(&migration_alone, &modern).is_err());
    Ok(())
}

fn scope() -> GrantScope {
    GrantScope {
        schema_version: 1,
        deployment_id: "10000000-0000-4000-8000-000000000001".into(),
        space_id: "20000000-0000-4000-8000-000000000002".into(),
        grant_id: "30000000-0000-4000-8000-000000000003".into(),
        policy_epoch: 7,
        not_before_ms: 1000,
        expires_at_ms: 2000,
    }
}

fn path() -> Result<GrantClaims, Box<dyn std::error::Error>> {
    Ok(GrantClaims::Path(PathClaims {
        scope: scope(),
        peers: PeerPair::new(PeerId([1; 32]), PeerId([2; 32]))?,
        purpose: Purpose::RemoteControl,
        connectivity_grant_digest: [8; 32],
        policy: PathPolicy {
            allow_direct: true,
            relays: vec![],
            max_hops: 0,
        },
    }))
}

#[test]
fn incompatible_purposes_spaces_epochs_and_paths_cannot_share_a_group()
-> Result<(), Box<dyn std::error::Error>> {
    let direct = path()?;
    let original = direct.unverified_transport_group_digest()?;
    let GrantClaims::Path(claims) = direct else {
        return Err("wrong fixture kind".into());
    };
    for change in 0..5 {
        let mut changed = claims.clone();
        match change {
            0 => changed.purpose = Purpose::PrivateService,
            1 => changed.scope.space_id = "20000000-0000-4000-8000-000000000004".into(),
            2 => changed.scope.policy_epoch += 1,
            3 => changed.scope.expires_at_ms += 1,
            _ => {
                changed.policy.relays = vec![PeerId([3; 32])];
                changed.policy.max_hops = 1;
            }
        }
        assert_ne!(
            original,
            GrantClaims::Path(changed).unverified_transport_group_digest()?
        );
    }
    Ok(())
}

#[test]
fn routes_reject_reflection_loops_unknown_relays_and_excess_hops()
-> Result<(), Box<dyn std::error::Error>> {
    let peers = PeerPair::new(PeerId([1; 32]), PeerId([2; 32]))?;
    let policy = PathPolicy {
        allow_direct: false,
        relays: vec![PeerId([3; 32]), PeerId([4; 32])],
        max_hops: 2,
    };
    assert!(policy.allows(peers, &[PeerId([3; 32]), PeerId([4; 32])]));
    for route in [
        vec![],
        vec![PeerId([1; 32])],
        vec![PeerId([5; 32])],
        vec![PeerId([3; 32]), PeerId([3; 32])],
        vec![PeerId([3; 32]), PeerId([4; 32]), PeerId([3; 32])],
    ] {
        assert!(!policy.allows(peers, &route));
    }
    Ok(())
}

#[test]
fn decoding_rejects_unknown_fields_kinds_duplicate_keys_and_noncanonical_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let claims = path()?;
    let canonical = claims.canonical_bytes()?;
    assert_eq!(GrantClaims::decode_canonical(&canonical)?, claims);
    let mut json: serde_json::Value = serde_json::from_slice(&canonical)?;
    json["claims"]["scope"]["extra_permission"] = true.into();
    assert!(GrantClaims::decode_canonical(&serde_json::to_vec(&json)?).is_err());
    let text = String::from_utf8(canonical.clone())?;
    let duplicate = text.replacen("\"kind\":", "\"kind\":\"path\",\"kind\":", 1);
    assert!(GrantClaims::decode_canonical(duplicate.as_bytes()).is_err());
    assert!(
        GrantClaims::decode_canonical(text.replace("\"path\"", "\"future_path\"").as_bytes())
            .is_err()
    );
    let mut whitespace = canonical;
    whitespace.push(b' ');
    assert!(GrantClaims::decode_canonical(&whitespace).is_err());
    assert!(GrantClaims::decode_canonical(&vec![b' '; CLAIM_BYTES + 1]).is_err());
    Ok(())
}

#[test]
fn membership_key_and_grant_kind_are_independent_of_admin_role()
-> Result<(), Box<dyn std::error::Error>> {
    let public_key = [9; 32];
    let mut member = MembershipClaims {
        scope: scope(),
        installation_id: "40000000-0000-4000-8000-000000000004".into(),
        peer: PeerId::from_public_key(&public_key),
        public_key,
        membership_epoch: 1,
        role: SpaceRole::Owner,
    };
    let membership = GrantClaims::Membership(member.clone());
    membership.validate()?;
    assert!(membership.unverified_transport_group_digest().is_err());
    member.public_key = [10; 32];
    assert!(GrantClaims::Membership(member).validate().is_err());
    Ok(())
}

#[test]
fn prefix_rules_reject_default_routes_host_bits_and_wrong_port_semantics()
-> Result<(), Box<dyn std::error::Error>> {
    for (network, prefix_len) in [
        ("0.0.0.0", 0),
        ("192.168.1.7", 24),
        ("::", 0),
        ("fd00::1", 64),
        ("fd00::", 129),
    ] {
        assert!(
            IpPrefix {
                network: network.parse()?,
                prefix_len
            }
            .validate()
            .is_err()
        );
    }
    let mut access = NetworkAccessClaims {
        scope: scope(),
        source: PeerId([1; 32]),
        destination: PeerId([2; 32]),
        source_prefixes: vec![IpPrefix {
            network: "10.0.0.1".parse()?,
            prefix_len: 32,
        }],
        destination_prefixes: vec![IpPrefix {
            network: "192.168.1.0".parse()?,
            prefix_len: 24,
        }],
        rules: vec![NetworkRule {
            protocol: IpProtocol::Tcp,
            direction: Direction::Inbound,
            ports: Some([22, 22]),
        }],
        byte_limit: 1024,
    };
    GrantClaims::NetworkAccess(access.clone()).validate()?;
    access.rules[0].ports = None;
    assert!(
        GrantClaims::NetworkAccess(access.clone())
            .validate()
            .is_err()
    );
    access.rules[0] = NetworkRule {
        protocol: IpProtocol::IcmpV6,
        direction: Direction::Inbound,
        ports: Some([22, 22]),
    };
    assert!(GrantClaims::NetworkAccess(access).validate().is_err());
    Ok(())
}
