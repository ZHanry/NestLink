use super::*;
use nestlink_protocol::{NODE_LEASE_MS, Permission, SCHEMA_VERSION};
fn id(n: u8) -> String {
    format!("{n:08x}-1111-4111-8111-111111111111")
}
fn permit() -> PermitClaims {
    PermitClaims {
        media_format_version: 0,
        media_formats: Vec::new(),
        media_format_sha256: Vec::new(),
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
fn allocation(p: &PermitClaims) -> Result<RelayAllocationClaims, ContractError> {
    Ok(RelayAllocationClaims {
        node_endpoint_revision: 0,
        schema_version: SCHEMA_VERSION,
        deployment_id: p.deployment_id.clone(),
        security_epoch: p.security_epoch,
        allocation_id: id(6),
        session_id: p.session_id.clone(),
        node_id: id(7),
        runtime_id: id(8),
        runtime_generation: 1,
        node_key_sha256: vec![4; 32],
        controller_device_id: p.controller_device_id.clone(),
        host_device_id: p.host_device_id.clone(),
        controller_key_sha256: p.controller_key_sha256.clone(),
        host_key_sha256: p.host_key_sha256.clone(),
        controller_account_id: p.account_id.clone(),
        host_account_id: id(9),
        connection_generation: p.connection_generation,
        policy_revision: p.policy_revision,
        quota_revision: 1,
        session_binding_sha256: session_binding(p)?.to_vec(),
        transports: vec![
            nestlink_protocol::RelayTransport::QuicDatagram as i32,
            nestlink_protocol::RelayTransport::WssStream as i32,
        ],
        grant_sequence: 1,
        issued_at_unix_ms: 1_000_000,
        expires_at_unix_ms: 1_010_000,
        bytes_per_second: 100000,
        bytes_per_allocation: 1000000,
    })
}
#[test]
fn signed_reservation_and_permit_domains_cannot_be_substituted() -> Result<(), ContractError> {
    let signer = PermitSigner::generate();
    let p = permit();
    let c = allocation(&p)?;
    let signed = signer.sign_relay_allocation(&c)?;
    assert!(
        verify_relay_allocation(
            &signed.encode_to_vec(),
            &PermitSigner::generate().public_key()
        )
        .is_err()
    );
    assert!(super::super::verify_permit(&signed.encode_to_vec(), &signer.public_key()).is_err());
    assert!(
        verify_relay_allocation(&signer.sign(&p)?.encode_to_vec(), &signer.public_key()).is_err()
    );
    let mut altered = signed.clone();
    altered.claims[0] ^= 1;
    assert!(verify_relay_allocation(&altered.encode_to_vec(), &signer.public_key()).is_err());
    assert!(verify_relay_allocation(&signed.encode_to_vec(), &signer.public_key())?.matches(&p)?);
    Ok(())
}
#[test]
fn renewal_changes_request_proof_without_changing_the_approved_session_binding()
-> Result<(), ContractError> {
    let signer = PermitSigner::generate();
    let p = permit();
    let c = allocation(&p)?;
    let verified = verify_relay_allocation(
        &signer.sign_relay_allocation(&c)?.encode_to_vec(),
        &signer.public_key(),
    )?;
    let mut renewed = p.clone();
    renewed.lease_sequence += 1;
    renewed.issued_at_unix_ms += 3000;
    renewed.expires_at_unix_ms += 3000;
    assert_eq!(session_binding(&p)?, session_binding(&renewed)?);
    assert!(verified.matches(&renewed)?);
    let original = allocation_transcript(
        &p,
        &p.account_id,
        &p.controller_device_id,
        &c.allocation_id,
        &c.node_id,
    )?;
    let current = allocation_transcript(
        &renewed,
        &p.account_id,
        &p.controller_device_id,
        &c.allocation_id,
        &c.node_id,
    )?;
    let installation = super::super::InstallationIdentity::generate();
    assert!(
        super::super::verify_device_action(
            &current,
            &installation.public_key(),
            &installation.sign_action(&original)?
        )
        .is_err()
    );
    renewed.permissions.push(Permission::Input as i32);
    assert!(!verified.matches(&renewed)?);
    Ok(())
}
#[test]
fn forged_duplicate_fields_fail_matching_even_with_an_unchanged_binding_digest()
-> Result<(), ContractError> {
    let signer = PermitSigner::generate();
    let p = permit();
    let original = allocation(&p)?;
    for mutation in 0..9 {
        let mut c = original.clone();
        match mutation {
            0 => c.deployment_id = id(10),
            1 => c.security_epoch += 1,
            2 => c.session_id = id(10),
            3 => c.controller_account_id = id(10),
            4 => c.controller_device_id = id(10),
            5 => c.host_device_id = id(10),
            6 => c.controller_key_sha256 = vec![7; 32],
            7 => c.connection_generation += 1,
            _ => c.policy_revision += 1,
        }
        let v = verify_relay_allocation(
            &signer.sign_relay_allocation(&c)?.encode_to_vec(),
            &signer.public_key(),
        )?;
        assert!(!v.matches(&p)?);
    }
    Ok(())
}
#[test]
fn allocation_bounds_reject_unknown_transports_long_leases_and_missing_generations()
-> Result<(), ContractError> {
    let original = allocation(&permit())?;
    for mutation in 0..7 {
        let mut c = original.clone();
        match mutation {
            0 => c.transports.push(c.transports[0]),
            1 => c.transports[0] = 99,
            2 => c.expires_at_unix_ms = c.issued_at_unix_ms + NODE_LEASE_MS + 1,
            3 => c.grant_sequence = 0,
            4 => c.runtime_id = "00000000-0000-0000-0000-000000000000".into(),
            5 => c.bytes_per_second = 0,
            _ => c.security_epoch = i64::MAX as u64 + 1,
        }
        assert!(c.validate().is_err());
    }
    Ok(())
}
