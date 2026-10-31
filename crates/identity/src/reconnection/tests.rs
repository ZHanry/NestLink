use super::*;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn recovery(previous: &PermitClaims) -> nestlink_protocol::api::NetworkRouteRecoveryChoice {
    let id = |n| format!("{n:08}-1111-4111-8111-111111111111");
    nestlink_protocol::api::NetworkRouteRecoveryChoice {
        version: 1,
        capability: NETWORK_RECOVERY_CAPABILITY.into(),
        space_id: id(6),
        route_set_id: id(7),
        path_grant_id: id(8),
        original_fingerprint: URL_SAFE_NO_PAD.encode([9; 32]),
        transport_group: URL_SAFE_NO_PAD.encode([10; 32]),
        previous_path_epoch: 1,
        target_node_id: id(11),
        target_route_binding: URL_SAFE_NO_PAD.encode([12; 32]),
        expires_at_unix_ms: previous.expires_at_unix_ms,
    }
}
fn fixture() -> Result<(PermitClaims, ReconnectionSubmission, PermitClaims)> {
    let id = |n| format!("{n:08}-1111-4111-8111-111111111111");
    let previous = PermitClaims {
        media_format_version: 0,
        media_formats: Vec::new(),
        media_format_sha256: Vec::new(),
        schema_version: SCHEMA_VERSION,
        deployment_id: id(1),
        security_epoch: 8,
        session_id: id(2),
        account_id: id(3),
        controller_device_id: id(4),
        host_device_id: id(5),
        resource_id: id(2),
        controller_key_sha256: vec![1; 32],
        host_key_sha256: vec![2; 32],
        capability_sha256: vec![3; 32],
        permissions: vec![1, 2],
        paths: vec![1, 2],
        policy_revision: 4,
        connection_generation: 2,
        lease_sequence: 7,
        issued_at_unix_ms: 1000000,
        expires_at_unix_ms: 1015000,
        required_capabilities: vec!["vp8".into()],
    };
    let choice = ReconnectionChoice {
        previous_permit_sha256: URL_SAFE_NO_PAD.encode(digest(&previous.encode_to_vec())),
        connection_generation: 3,
        lease_sequence: 8,
        nonce: URL_SAFE_NO_PAD.encode([11; 32]),
        network_recovery: None,
    };
    let request = ReconnectionSubmission {
        choice,
        controller_signature: URL_SAFE_NO_PAD.encode([5; 64]),
        host_signature: URL_SAFE_NO_PAD.encode([6; 64]),
    };
    let mut next = previous.clone();
    next.connection_generation = 3;
    next.lease_sequence = 8;
    next.issued_at_unix_ms = 1001000;
    validate_successor(&previous, &next, &request.choice)?;
    Ok((previous, request, next))
}
#[test]
fn legacy_choice_preserves_exact_json_transcript_and_new_contract_is_explicit() -> Result {
    let (previous, mut request, next) = fixture()?;
    let legacy_json = format!(
        "{{\"previous_permit_sha256\":\"{}\",\"connection_generation\":3,\"lease_sequence\":8,\"nonce\":\"{}\"}}",
        request.choice.previous_permit_sha256, request.choice.nonce
    );
    assert_eq!(serde_json::to_vec(&request.choice)?, legacy_json.as_bytes());
    let decoded: ReconnectionChoice = serde_json::from_str(&legacy_json)?;
    assert_eq!(decoded, request.choice);
    assert!(decoded.network_recovery.is_none());
    let old = transcript(&previous, &previous.host_device_id, &request.choice)?;
    request.choice.network_recovery = Some(recovery(&previous));
    validate_successor(&previous, &next, &request.choice)?;
    assert_ne!(
        transcript(&previous, &previous.host_device_id, &request.choice)?.payload_sha256,
        old.payload_sha256
    );
    let signer = PermitSigner::generate();
    let signed = signer
        .sign_reconnection(&previous, &request, &next)?
        .encode_to_vec();
    verify_reconnection(&signed, &signer.public_key(), &previous, &request)?;
    let original = request.clone();
    for variant in 0..7 {
        let mut changed = original.clone();
        let recovery = changed.choice.network_recovery.as_mut().ok_or("recovery")?;
        match variant {
            0 => recovery.target_node_id = "00000013-1111-4111-8111-111111111111".into(),
            1 => recovery.target_route_binding = URL_SAFE_NO_PAD.encode([13; 32]),
            2 => recovery.original_fingerprint = URL_SAFE_NO_PAD.encode([14; 32]),
            3 => recovery.transport_group = URL_SAFE_NO_PAD.encode([15; 32]),
            4 => recovery.capability = "path-migration-v1".into(),
            5 => recovery.previous_path_epoch = 2,
            _ => recovery.expires_at_unix_ms += 1,
        }
        assert!(verify_reconnection(&signed, &signer.public_key(), &previous, &changed).is_err());
    }
    let a = network_recovery_id(&previous, &request.choice, "allocation")?;
    assert_eq!(
        a,
        network_recovery_id(&previous, &request.choice, "allocation")?
    );
    assert_ne!(a, network_recovery_id(&previous, &request.choice, "path")?);
    assert!(nestlink_protocol::valid_id(&a));
    assert!(network_recovery_id(&previous, &decoded, "allocation").is_err());
    Ok(())
}
#[test]
fn reconnect_grant_binds_exact_request_nonce_root_and_original_permit() -> Result {
    let (previous, request, next) = fixture()?;
    let signer = PermitSigner::generate();
    let grant = signer
        .sign_reconnection(&previous, &request, &next)?
        .encode_to_vec();
    assert_eq!(
        grant,
        signer
            .sign_reconnection(&previous, &request, &next)?
            .encode_to_vec()
    );
    let verified = verify_reconnection(&grant, &signer.public_key(), &previous, &request)?;
    assert_eq!(verified.claims(), &next);
    assert_eq!(verified.issuer(), signer.public_key());
    assert!(
        verify_reconnection(
            &grant,
            &PermitSigner::generate().public_key(),
            &previous,
            &request
        )
        .is_err()
    );
    for variant in 0..3 {
        let mut changed = request.clone();
        match variant {
            0 => changed.choice.nonce = URL_SAFE_NO_PAD.encode([9; 32]),
            1 => changed.controller_signature = URL_SAFE_NO_PAD.encode([8; 64]),
            _ => changed.host_signature = URL_SAFE_NO_PAD.encode([9; 64]),
        };
        assert!(verify_reconnection(&grant, &signer.public_key(), &previous, &changed).is_err());
    }
    let mut old = previous.clone();
    old.permissions = vec![1];
    assert!(verify_reconnection(&grant, &signer.public_key(), &old, &request).is_err());
    Ok(())
}
#[test]
fn successor_cannot_extend_deadline_expand_consent_or_skip_generations() -> Result {
    let (previous, request, next) = fixture()?;
    for variant in 0..6 {
        let mut changed = next.clone();
        match variant {
            0 => changed.expires_at_unix_ms += 1,
            1 => changed.permissions.push(3),
            2 => changed.paths = vec![2],
            3 => changed.connection_generation += 1,
            4 => changed.host_key_sha256 = vec![9; 32],
            _ => changed.issued_at_unix_ms = 999999,
        };
        assert!(validate_successor(&previous, &changed, &request.choice).is_err());
        assert!(
            PermitSigner::generate()
                .sign_reconnection(&previous, &request, &changed)
                .is_err()
        );
    }
    let mut choice = request.choice.clone();
    choice.connection_generation = i64::MAX as u64 + 1;
    assert!(validate_choice(&previous, &choice).is_err());
    choice = request.choice.clone();
    choice.nonce.push('=');
    assert!(validate_choice(&previous, &choice).is_err());
    Ok(())
}
#[test]
fn grant_purpose_signature_and_envelope_budget_fail_closed() -> Result {
    let (previous, request, next) = fixture()?;
    let signer = PermitSigner::generate();
    let mut signed = signer.sign_reconnection(&previous, &request, &next)?;
    signed.signature[0] ^= 1;
    assert!(
        verify_reconnection(
            &signed.encode_to_vec(),
            &signer.public_key(),
            &previous,
            &request
        )
        .is_err()
    );
    let permit = signer.sign(&next)?.encode_to_vec();
    assert!(verify_reconnection(&permit, &signer.public_key(), &previous, &request).is_err());
    assert!(
        verify_reconnection(
            &vec![0; (RECONNECTION_BYTES + 129) as usize],
            &signer.public_key(),
            &previous,
            &request
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn successor_preserves_complete_media_format_scope_not_only_legacy_capability_digest() -> Result {
    use nestlink_protocol::media_format::{FormatSet, FrameRate, VideoFormat};
    let (mut previous, mut request, mut next) = fixture()?;
    let format = VideoFormat::legacy_h264(31, 320, 240, FrameRate::new(30, 1)?, 2000)?;
    let set = FormatSet::new(vec![format])?;
    previous
        .required_capabilities
        .push(nestlink_protocol::media_authority::FORMAT_CAPABILITY.into());
    previous.media_format_version = 2;
    previous.media_formats = vec![format.encode()?];
    previous.media_format_sha256 = set.digest().to_vec();
    request.choice.previous_permit_sha256 =
        URL_SAFE_NO_PAD.encode(digest(&previous.encode_to_vec()));
    next.media_format_version = 2;
    next.media_formats = previous.media_formats.clone();
    next.media_format_sha256 = previous.media_format_sha256.clone();
    next.required_capabilities = previous.required_capabilities.clone();
    validate_successor(&previous, &next, &request.choice)?;
    let changed = VideoFormat::legacy_h264(31, 320, 240, FrameRate::new(30, 1)?, 1000)?;
    let changed_set = FormatSet::new(vec![changed])?;
    next.media_formats = vec![changed.encode()?];
    next.media_format_sha256 = changed_set.digest().to_vec();
    assert!(validate_successor(&previous, &next, &request.choice).is_err());
    Ok(())
}
