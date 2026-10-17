use super::*;
use crate::{InstallationIdentity, PermitSigner, digest};
use ed25519_dalek::{Signer, SigningKey};
use nestlink_protocol::{
    SCHEMA_VERSION, SignedTurnCredentials, SignedTurnPeerBinding, SignedTurnResourceQuery,
    SignedTurnResourceSnapshot, TurnCredentialsClaims, TurnPeerBindingClaims, TurnPurpose,
    TurnResourceQueryClaims, TurnResourceSnapshotClaims,
};
use prost::Message;

fn id(number: u32) -> String {
    format!("{number:08x}-1111-4111-8111-111111111111")
}

fn query() -> TurnResourceQueryClaims {
    TurnResourceQueryClaims {
        schema_version: SCHEMA_VERSION,
        deployment_id: id(1),
        security_epoch: 1,
        node_id: id(2),
        runtime_id: id(3),
        runtime_generation: 1,
        policy_revision: 1,
        lease_sequence: 1,
        request_id: id(4),
        request_sequence: 1,
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: 2_000,
    }
}

fn credentials() -> TurnCredentialsClaims {
    TurnCredentialsClaims {
        schema_version: SCHEMA_VERSION,
        deployment_id: id(1),
        security_epoch: 1,
        session_id: id(2),
        allocation_id: id(3),
        device_id: id(4),
        temporary_identity: id(5),
        purpose: TurnPurpose::BrowserWebRtc as i32,
        node_id: id(6),
        runtime_id: id(7),
        runtime_generation: 1,
        network_generation: 1,
        connection_generation: 1,
        lease_sequence: 1,
        permit_sha256: vec![1; 32],
        request_sha256: vec![2; 32],
        grant_sequence: 1,
        endpoint_revision: 1,
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: 2_000,
        username: "nl:allocation".into(),
        realm: "nestlink-test".into(),
        password: "A".repeat(43),
        endpoints: vec!["turns:turn.example.test:443?transport=tcp".into()],
        allow_loopback: false,
    }
}

fn peer_binding(
    controller: &InstallationIdentity,
    host: &InstallationIdentity,
) -> TurnPeerBindingClaims {
    TurnPeerBindingClaims {
        schema_version: SCHEMA_VERSION,
        deployment_id: id(1),
        security_epoch: 1,
        session_id: id(2),
        temporary_identity: id(3),
        purpose: TurnPurpose::BrowserWebRtc as i32,
        controller_allocation_id: id(4),
        host_allocation_id: id(5),
        controller_device_id: id(3),
        host_device_id: id(6),
        controller_key_sha256: digest(&controller.public_key()).to_vec(),
        host_key_sha256: digest(&host.public_key()).to_vec(),
        controller_network_generation: 1,
        host_network_generation: 1,
        connection_generation: 1,
        lease_sequence: 1,
        permit_sha256: vec![7; 32],
        controller_candidates: vec!["8.8.8.8:40000".into()],
        host_candidates: vec!["1.1.1.1:50000".into()],
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: 2_000,
    }
}

fn snapshot(query: TurnResourceQueryClaims, query_sha256: Vec<u8>) -> TurnResourceSnapshotClaims {
    TurnResourceSnapshotClaims {
        query: Some(query),
        query_sha256,
        snapshot_sequence: 1,
        quota_revision: 1,
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: 2_000,
        grants: vec![],
        peer_bindings: vec![],
    }
}

fn signature(key: &SigningKey, domain: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(domain.len() + bytes.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(bytes);
    key.sign(&message).to_bytes().to_vec()
}

fn append_duplicate_epoch(bytes: &[u8]) -> Vec<u8> {
    let mut noncanonical = bytes.to_vec();
    // Field 3 is security_epoch in each claim type used below. Repeating the
    // same value preserves the decoded meaning but is not canonical protobuf.
    noncanonical.extend_from_slice(&[0x18, 0x01]);
    noncanonical
}

fn append_unknown_field(bytes: &[u8]) -> Vec<u8> {
    let mut noncanonical = bytes.to_vec();
    // Field 100, varint wire type, value 1.
    noncanonical.extend_from_slice(&[0xa0, 0x06, 0x01]);
    noncanonical
}

fn overlong_schema_varint(bytes: &[u8]) -> Vec<u8> {
    assert_eq!(bytes.first(), Some(&0x08));
    assert!(bytes[1] < 0x80);
    let mut noncanonical = vec![0x08, bytes[1] | 0x80, 0x00];
    noncanonical.extend_from_slice(&bytes[2..]);
    noncanonical
}

fn policy_key(seed: &[u8; 32]) -> Result<SigningKey, std::io::Error> {
    let mut derived = [0; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(Some(b"NestLink/v15/deployment-signing-keys/v1"), seed)
        .expand(b"node-policy-ed25519", &mut derived)
        .map_err(|_| std::io::Error::other("node policy key derivation failed"))?;
    Ok(SigningKey::from_bytes(&derived))
}

#[test]
fn turn_signatures_are_purpose_separated_and_tamper_and_wrong_keys_fail()
-> Result<(), Box<dyn std::error::Error>> {
    let node = NodeIdentity::from_seed(&[11; 32]);
    let other_node = NodeIdentity::from_seed(&[12; 32]);
    let signed_query = node.sign_turn_resource_query(&query())?;
    assert!(verify_turn_resource_query(&signed_query, &node.public_key()).is_ok());
    assert!(verify_turn_resource_query(&signed_query, &other_node.public_key()).is_err());

    let mut tampered_query = signed_query.clone();
    tampered_query.claims[0] ^= 1;
    assert!(verify_turn_resource_query(&tampered_query, &node.public_key()).is_err());

    let permit_issuer = PermitSigner::from_seed([13; 32]);
    let signed_credentials = permit_issuer.sign_turn_credentials(&credentials())?;
    assert!(verify_turn_credentials(&signed_credentials, &permit_issuer.public_key()).is_ok());
    assert!(verify_turn_credentials(&signed_credentials, &node.public_key()).is_err());

    let query_as_credentials = SignedTurnCredentials {
        claims: signed_query.claims.clone(),
        signature: signed_query.signature.clone(),
    };
    assert!(verify_turn_credentials(&query_as_credentials, &node.public_key()).is_err());
    let credentials_as_query = SignedTurnResourceQuery {
        claims: signed_credentials.claims.clone(),
        signature: signed_credentials.signature.clone(),
    };
    assert!(
        verify_turn_resource_query(&credentials_as_query, &permit_issuer.public_key()).is_err()
    );
    Ok(())
}

#[test]
fn query_verification_rejects_duplicate_unknown_and_nonminimal_varint_bytes() {
    let seed = [21; 32];
    let key = SigningKey::from_bytes(&seed);
    let identity = NodeIdentity::from_seed(&seed);
    let claims = query().encode_to_vec();
    let noncanonical = [
        append_duplicate_epoch(&claims),
        append_unknown_field(&claims),
        overlong_schema_varint(&claims),
    ];
    for bytes in noncanonical {
        let signed = SignedTurnResourceQuery {
            signature: signature(&key, super::QUERY, &bytes),
            claims: bytes,
        };
        assert!(verify_turn_resource_query(&signed, &identity.public_key()).is_err());
    }
}

#[test]
fn credentials_snapshot_and_peer_claims_reject_signed_noncanonical_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let issuer_seed = [31; 32];
    let issuer_key = SigningKey::from_bytes(&issuer_seed);
    let credentials_bytes = append_unknown_field(&credentials().encode_to_vec());
    let signed_credentials = SignedTurnCredentials {
        signature: signature(&issuer_key, super::CREDENTIALS, &credentials_bytes),
        claims: credentials_bytes,
    };
    assert!(
        verify_turn_credentials(&signed_credentials, &issuer_key.verifying_key().to_bytes())
            .is_err()
    );

    let controller = InstallationIdentity::from_seed([32; 32]);
    let host = InstallationIdentity::from_seed([33; 32]);
    let binding_bytes = append_duplicate_epoch(&peer_binding(&controller, &host).encode_to_vec());
    let binding_signature = signature(
        &SigningKey::from_bytes(&[32; 32]),
        super::PEERS,
        &binding_bytes,
    );
    assert!(
        verify_turn_peer_signature(&binding_bytes, &controller.public_key(), &binding_signature)
            .is_err()
    );

    let query_identity = NodeIdentity::from_seed(&[34; 32]);
    let signed_query = query_identity.sign_turn_resource_query(&query())?;
    let valid_snapshot = snapshot(query(), digest(&signed_query.claims).to_vec());
    let snapshot_bytes = append_unknown_field(&valid_snapshot.encode_to_vec());
    let policy_seed = [35; 32];
    let signed_snapshot = SignedTurnResourceSnapshot {
        signature: signature(&policy_key(&policy_seed)?, super::SNAPSHOT, &snapshot_bytes),
        claims: snapshot_bytes,
    };
    let policy_signer = NodePolicySigner::from_master_seed(&policy_seed)?;
    assert!(verify_turn_resource_snapshot(
        &signed_snapshot,
        &policy_signer.public_key(),
        &signed_query,
    )
    .is_err());

    let mut bad_nested = snapshot(query(), vec![1; 32]);
    bad_nested.peer_bindings.push(SignedTurnPeerBinding {
        claims: append_unknown_field(&peer_binding(&controller, &host).encode_to_vec()),
        controller_signature: vec![0; 64],
        host_signature: vec![0; 64],
    });
    assert!(validate_canonical_peer_bindings(&bad_nested).is_err());
    Ok(())
}

#[test]
fn snapshot_query_epoch_and_peer_roles_are_bound_to_the_expected_authorities()
-> Result<(), Box<dyn std::error::Error>> {
    let node = NodeIdentity::from_seed(&[41; 32]);
    let signed_query = node.sign_turn_resource_query(&query())?;
    let policy = NodePolicySigner::from_master_seed(&[42; 32])?;

    let mut wrong_epoch = query();
    wrong_epoch.security_epoch = 2;
    let mismatch = snapshot(wrong_epoch, digest(&signed_query.claims).to_vec());
    let signed_mismatch = policy.sign_turn_resource_snapshot(&mismatch)?;
    assert!(
        verify_turn_resource_snapshot(&signed_mismatch, &policy.public_key(), &signed_query)
            .is_err()
    );

    let controller = InstallationIdentity::from_seed([43; 32]);
    let host = InstallationIdentity::from_seed([44; 32]);
    let claims = peer_binding(&controller, &host);
    let signed = SignedTurnPeerBinding {
        claims: claims.encode_to_vec(),
        controller_signature: controller.sign_turn_peer_binding(&claims)?,
        host_signature: host.sign_turn_peer_binding(&claims)?,
    };
    assert!(
        verify_turn_peer_binding(&signed, &controller.public_key(), &host.public_key()).is_ok()
    );

    let swapped = SignedTurnPeerBinding {
        claims: signed.claims.clone(),
        controller_signature: signed.host_signature.clone(),
        host_signature: signed.controller_signature.clone(),
    };
    assert!(
        verify_turn_peer_binding(&swapped, &controller.public_key(), &host.public_key()).is_err()
    );

    let tampered = SignedTurnPeerBinding {
        claims: append_duplicate_epoch(&signed.claims),
        controller_signature: signed.controller_signature,
        host_signature: signed.host_signature,
    };
    assert!(
        verify_turn_peer_binding(&tampered, &controller.public_key(), &host.public_key()).is_err()
    );

    let valid_snapshot = snapshot(query(), digest(&signed_query.claims).to_vec());
    let snapshot_bytes = valid_snapshot.encode_to_vec();
    let query_domain_signature = signature(
        &SigningKey::from_bytes(&[41; 32]),
        super::QUERY,
        &snapshot_bytes,
    );
    let wrong_purpose = SignedTurnResourceSnapshot {
        claims: snapshot_bytes,
        signature: query_domain_signature,
    };
    assert!(
        verify_turn_resource_snapshot(&wrong_purpose, &node.public_key(), &signed_query).is_err()
    );
    Ok(())
}
