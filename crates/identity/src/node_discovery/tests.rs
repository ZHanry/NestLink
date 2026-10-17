use super::*;
use nestlink_protocol::{DiscoveredRelayNode, Path, Permission, SCHEMA_VERSION};
type Result<T = ()> = std::result::Result<T, ContractError>;
fn id(n: u8) -> String {
    format!("{n:08x}-1111-4111-8111-111111111111")
}
fn permit() -> PermitClaims {
    PermitClaims {
        schema_version: SCHEMA_VERSION,
        deployment_id: id(1),
        security_epoch: 1,
        session_id: id(2),
        account_id: id(3),
        controller_device_id: id(4),
        host_device_id: id(5),
        controller_key_sha256: vec![1; 32],
        host_key_sha256: vec![2; 32],
        resource_id: id(5),
        permissions: vec![Permission::View as i32],
        paths: vec![Path::Relay as i32],
        policy_revision: 2,
        connection_generation: 1,
        lease_sequence: 1,
        issued_at_unix_ms: 1_000_000,
        expires_at_unix_ms: 1_015_000,
        capability_sha256: vec![3; 32],
        required_capabilities: vec!["vp8".into()],
    }
}
fn claims(p: &PermitClaims) -> Result<NodeDiscoveryClaims> {
    let t = discovery_transcript(p, &p.account_id, &p.controller_device_id, &[9; 32])?;
    Ok(NodeDiscoveryClaims {
        schema_version: SCHEMA_VERSION,
        deployment_id: p.deployment_id.clone(),
        security_epoch: 1,
        session_id: p.session_id.clone(),
        account_id: p.account_id.clone(),
        device_id: p.controller_device_id.clone(),
        device_key_sha256: p.controller_key_sha256.clone(),
        permit_sha256: digest(&p.encode_to_vec()).to_vec(),
        request_sha256: digest(&t.encode_to_vec()).to_vec(),
        nonce: vec![9; 32],
        issued_at_unix_ms: 1_000_001,
        expires_at_unix_ms: 1_005_001,
        nodes: vec![DiscoveredRelayNode {
            node_id: id(6),
            node_key_sha256: vec![4; 32],
            runtime_id: id(7),
            runtime_generation: 1,
            endpoint_revision: 1,
            quic_uri: "quic://relay.example:28743".into(),
            wss_origin: "https://relay.example".into(),
            allow_loopback: false,
            expires_at_unix_ms: 1_005_001,
        }],
    })
}
#[test]
fn discovery_signatures_bind_entire_node_descriptors_and_reject_other_issuers_and_purposes()
-> Result {
    let s = PermitSigner::generate();
    let p = permit();
    let c = claims(&p)?;
    let signed = s.sign_node_discovery(&c)?;
    assert!(
        verify_node_discovery(
            &signed.encode_to_vec(),
            &PermitSigner::generate().public_key()
        )
        .is_err()
    );
    assert!(crate::verify_permit(&signed.encode_to_vec(), &s.public_key()).is_err());
    assert!(verify_node_discovery(&s.sign(&p)?.encode_to_vec(), &s.public_key()).is_err());
    for change in 0..7 {
        let mut c = c.clone();
        match change {
            0 => c.nodes[0].quic_uri = "quic://other.example:443".into(),
            1 => c.nodes[0].wss_origin = "https://other.example".into(),
            2 => c.nodes[0].runtime_generation += 1,
            3 => c.nodes[0].endpoint_revision += 1,
            4 => c.nodes[0].node_key_sha256[0] ^= 1,
            5 => c.nodes[0].allow_loopback = true,
            _ => c.nodes[0].expires_at_unix_ms -= 1,
        }
        let mut forged = signed.clone();
        forged.claims = c.encode_to_vec();
        assert!(verify_node_discovery(&forged.encode_to_vec(), &s.public_key()).is_err());
    }
    Ok(())
}
#[test]
fn fresh_discovery_is_bound_to_full_permit_endpoint_request_and_nonce() -> Result {
    let s = PermitSigner::generate();
    let p = permit();
    let c = claims(&p)?;
    let v = verify_node_discovery(&s.sign_node_discovery(&c)?.encode_to_vec(), &s.public_key())?;
    assert!(v.matches(&p, &p.account_id, &p.controller_device_id, &[9; 32])?);
    assert!(!v.matches(&p, &p.account_id, &p.controller_device_id, &[8; 32])?);
    assert!(!v.matches(&p, &id(8), &p.controller_device_id, &[9; 32])?);
    assert!(!v.matches(&p, &p.account_id, &p.host_device_id, &[9; 32])?);
    for change in 0..4 {
        let mut p = p.clone();
        match change {
            0 => p.lease_sequence += 1,
            1 => p.connection_generation += 1,
            2 => p.policy_revision += 1,
            _ => {
                p.issued_at_unix_ms += 1;
                p.expires_at_unix_ms += 1;
            }
        }
        assert!(!v.matches(&p, &p.account_id, &p.controller_device_id, &[9; 32])?);
    }
    let mut direct = p.clone();
    direct.paths = vec![Path::Direct as i32];
    assert!(
        discovery_transcript(&direct, &p.account_id, &p.controller_device_id, &[9; 32]).is_err()
    );
    Ok(())
}
#[test]
fn discovery_rejects_excess_nodes_duplicates_unbounded_lifetimes_and_empty_locations() -> Result {
    let s = PermitSigner::generate();
    let p = permit();
    let c = claims(&p)?;
    for change in 0..6 {
        let mut c = c.clone();
        match change {
            0 => c.expires_at_unix_ms += 1,
            1 => c.nodes[0].expires_at_unix_ms += 1,
            2 => c.nodes.push(c.nodes[0].clone()),
            3 => c.nodes = vec![c.nodes[0].clone(); 17],
            4 => {
                c.nodes[0].quic_uri.clear();
                c.nodes[0].wss_origin.clear();
            }
            _ => c.nodes[0].endpoint_revision = 0,
        }
        assert!(s.sign_node_discovery(&c).is_err());
    }
    Ok(())
}
