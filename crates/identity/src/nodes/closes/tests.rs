use super::*;
use nestlink_protocol::SCHEMA_VERSION;
fn id(n: u8) -> String {
    format!("{n:08x}-1111-4111-8111-111111111111")
}
fn claims() -> RelayCloseClaims {
    RelayCloseClaims {
        schema_version: SCHEMA_VERSION,
        deployment_id: id(1),
        security_epoch: 1,
        node_id: id(2),
        runtime_id: id(3),
        runtime_generation: 4,
        allocation_id: id(5),
        allocation_binding_sha256: vec![6; 32],
        observed_grant_sequence: 7,
        opened_connections: 2,
        closed_connections: 2,
        admitted_bytes: 123,
        closed_at_unix_ms: 10000,
    }
}
#[test]
fn relay_close_rejects_partial_facts_wrong_keys_domains_tampering_and_oversize()
-> Result<(), ContractError> {
    let node = NodeIdentity::generate();
    let c = claims();
    let signed = node.sign_relay_close(&c)?;
    assert_eq!(verify_relay_close(&signed, &node.public_key())?, c);
    assert!(verify_relay_close(&signed, &NodeIdentity::generate().public_key()).is_err());
    let mut wrong = signed.clone();
    wrong.signature[0] ^= 1;
    assert!(verify_relay_close(&wrong, &node.public_key()).is_err());
    wrong = signed.clone();
    wrong.claims = RelayCloseClaims {
        admitted_bytes: 124,
        ..c.clone()
    }
    .encode_to_vec();
    assert!(verify_relay_close(&wrong, &node.public_key()).is_err());
    wrong.signature = node
        .key
        .sign(&domain_message(
            b"NestLink/v15/node-usage-report/v1\0",
            &wrong.claims,
        ))
        .to_bytes()
        .to_vec();
    assert!(verify_relay_close(&wrong, &node.public_key()).is_err());
    let partial = RelayCloseClaims {
        closed_connections: 1,
        ..c
    };
    assert!(node.sign_relay_close(&partial).is_err());
    let partial_bytes = partial.encode_to_vec();
    let partial_signed = SignedRelayClose {
        signature: node
            .key
            .sign(&domain_message(CLOSE, &partial_bytes))
            .to_bytes()
            .to_vec(),
        claims: partial_bytes,
    };
    assert!(verify_relay_close(&partial_signed, &node.public_key()).is_err());
    wrong.claims = vec![0; RELAY_CLOSE_MESSAGE_BYTES as usize + 1];
    assert_eq!(
        verify_relay_close(&wrong, &node.public_key())
            .err()
            .map(|e| e.code),
        Some(ErrorCode::CapacityExceeded)
    );
    Ok(())
}
#[test]
fn close_ack_binds_exact_payload_and_separate_control_signing_purpose() -> Result<(), ContractError>
{
    let node = NodeIdentity::generate();
    let control = NodePolicySigner::from_master_seed(&[7; 32])?;
    let c = claims();
    let request = node.sign_relay_close(&c)?;
    let ack = RelayCloseAckClaims {
        schema_version: SCHEMA_VERSION,
        deployment_id: c.deployment_id,
        security_epoch: c.security_epoch,
        node_id: c.node_id,
        runtime_id: c.runtime_id,
        runtime_generation: c.runtime_generation,
        allocation_id: c.allocation_id,
        close_sha256: digest(&request.claims).to_vec(),
        accepted_at_unix_ms: 10001,
        released_endpoint_slots: 2,
    };
    let signed = control.sign_relay_close_ack(&ack)?;
    assert_eq!(
        verify_relay_close_ack(&signed, &control.public_key(), &request)?,
        ack
    );
    let mut other = claims();
    other.admitted_bytes += 1;
    assert!(
        verify_relay_close_ack(
            &signed,
            &control.public_key(),
            &node.sign_relay_close(&other)?
        )
        .is_err()
    );
    let mut forged = signed.clone();
    forged.signature = control
        .key
        .sign(&domain_message(CLOSE, &signed.claims))
        .to_bytes()
        .to_vec();
    assert!(verify_relay_close_ack(&forged, &control.public_key(), &request).is_err());
    assert!(
        verify_relay_close_ack(
            &signed,
            &NodePolicySigner::from_master_seed(&[8; 32])?.public_key(),
            &request
        )
        .is_err()
    );
    Ok(())
}
