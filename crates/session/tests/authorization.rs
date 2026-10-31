#![allow(clippy::unwrap_used, clippy::expect_used)]
use nestlink_identity::{InstallationIdentity, PermitSigner, verify_permit};
use nestlink_policy::PathSet;
use nestlink_protocol::{ErrorCode, Path, Permission, PermitClaims, SCHEMA_VERSION, SignedPermit};
use nestlink_session::{
    ClockSample, EndpointRole, Session, SessionBinding, SessionState, StopReason,
};
use prost::Message;

fn id(n: u8) -> String {
    format!("{n:08x}-1111-4111-8111-111111111111")
}
fn fixture() -> (
    PermitSigner,
    InstallationIdentity,
    InstallationIdentity,
    PermitClaims,
    SessionBinding,
) {
    let signer = PermitSigner::from_seed([1; 32]);
    let controller = InstallationIdentity::from_seed([2; 32]);
    let host = InstallationIdentity::from_seed([3; 32]);
    let claims = PermitClaims {
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
        controller_key_sha256: controller.fingerprint().to_vec(),
        host_key_sha256: host.fingerprint().to_vec(),
        resource_id: id(6),
        permissions: vec![Permission::View as i32, Permission::Input as i32],
        paths: vec![Path::Direct as i32],
        policy_revision: 1,
        connection_generation: 1,
        lease_sequence: 1,
        issued_at_unix_ms: 1_000_000,
        expires_at_unix_ms: 1_015_000,
        capability_sha256: vec![7; 32],
        required_capabilities: vec!["vp8".into()],
    };
    let binding = SessionBinding {
        media: None,
        deployment_id: id(1),
        security_epoch: 1,
        session_id: id(2),
        account_id: id(3),
        controller_device_id: id(4),
        host_device_id: id(5),
        controller_key_sha256: controller.fingerprint(),
        host_key_sha256: host.fingerprint(),
        resource_id: id(6),
        policy_revision: 1,
        connection_generation: 1,
        capability_sha256: [7; 32],
        granted_permissions: vec![Permission::View, Permission::Input],
        supported_capabilities: vec!["vp8".into()],
        local_paths: PathSet::DIRECT,
    };
    (signer, controller, host, claims, binding)
}

#[test]
fn signed_permit_matches_independent_protobuf_and_ed25519_vector() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/vectors/session-permit-v1.json"
    ))
    .unwrap();
    let (signer, _, _, claims, _) = fixture();
    let signed = signer.sign(&claims).unwrap();
    let hex = |bytes: &[u8]| bytes.iter().map(|v| format!("{v:02x}")).collect::<String>();
    assert_eq!(hex(&signer.public_key()), vector["issuer_public_key_hex"]);
    assert_eq!(hex(&signed.claims), vector["claims_hex"]);
    assert_eq!(hex(&signed.signature), vector["signature_hex"]);
    assert_eq!(hex(&signed.encode_to_vec()), vector["envelope_hex"]);
}
fn verified(signer: &PermitSigner, claims: &PermitClaims) -> nestlink_identity::VerifiedPermit {
    verify_permit(
        &signer.sign(claims).unwrap().encode_to_vec(),
        &signer.public_key(),
    )
    .unwrap()
}
fn activate(signer: &PermitSigner, claims: &PermitClaims, binding: SessionBinding) -> Session {
    Session::activate(
        verified(signer, claims),
        binding,
        Path::Direct,
        1000,
        ClockSample {
            monotonic_ms: 1000,
            unix_ms: 1_000_000,
        },
    )
    .unwrap()
}

#[test]
fn remote_budget_original_session_requires_verified_budget_and_retains_meter_during_renewal()
-> Result<(), Box<dyn std::error::Error>> {
    use nestlink_protocol::remote_budget::*;
    let (signer, _, _, mut claims, mut binding) = fixture();
    claims.required_capabilities.push(CAPABILITY.into());
    binding.supported_capabilities.push(CAPABILITY.into());
    let now = ClockSample {
        monotonic_ms: 1000,
        unix_ms: 1_000_000,
    };
    assert!(
        Session::activate(
            verified(&signer, &claims),
            binding.clone(),
            Path::Direct,
            1000,
            now
        )
        .is_err()
    );
    let budget = RemoteUsageBudgetClaims {
        version: 1,
        reservation_id: id(90),
        deployment_id: claims.deployment_id.clone(),
        security_epoch: claims.security_epoch,
        session_id: claims.session_id.clone(),
        account_id: claims.account_id.clone(),
        controller_device_id: claims.controller_device_id.clone(),
        host_device_id: claims.host_device_id.clone(),
        controller_key_sha256: claims.controller_key_sha256.as_slice().try_into()?,
        host_key_sha256: claims.host_key_sha256.as_slice().try_into()?,
        resource_id: claims.resource_id.clone(),
        connection_generation: claims.connection_generation,
        policy_revision: claims.policy_revision,
        capability_sha256: claims.capability_sha256.as_slice().try_into()?,
        permissions: claims.permissions.clone(),
        paths: claims.paths.clone(),
        maximum_bytes: 100,
        maximum_file_write_bytes: 0,
        maximum_connection_attempts: 8,
    };
    let permit = verified(&signer, &claims)
        .with_remote_budget(&signer.sign_remote_usage_budget(&budget)?)?;
    let observer = permit.remote_budget().ok_or("meter")?.clone();
    let mut session = Session::activate(permit.clone(), binding, Path::Direct, 1000, now)?;
    observer.charge(Permission::View, 70)?;
    claims.lease_sequence = 2;
    claims.issued_at_unix_ms += 1000;
    claims.expires_at_unix_ms += 1000;
    let next = verified(&signer, &claims).retain_remote_budget(&permit)?;
    session.renew(
        next,
        2000,
        ClockSample {
            monotonic_ms: 2000,
            unix_ms: 1_001_000,
        },
    )?;
    assert_eq!(
        session
            .current_verified_permit()
            .remote_budget()
            .ok_or("retained meter")?
            .spent_bytes()?,
        70
    );
    assert!(observer.charge(Permission::View, 31).is_err());
    assert!(
        session
            .check_clock(ClockSample {
                monotonic_ms: 2001,
                unix_ms: 1_001_001
            })
            .is_err()
    );
    assert_eq!(session.state(), SessionState::Stopped(StopReason::Revoked));
    Ok(())
}

#[test]
fn remote_budget_offline_original_session_uses_independent_deadline_and_never_exports_or_renews_online_authority()
-> Result<(), Box<dyn std::error::Error>> {
    use nestlink_identity::{network::NetworkAuthoritySigner, offline::*};
    use nestlink_protocol::offline::*;
    let (signer, controller, host, claims, binding) = fixture();
    let mut process = OfflineProcess::new(
        claims.controller_device_id.clone(),
        controller.public_key(),
        1_000_000,
        1,
    )?;
    let host_process = OfflineProcess::new(
        claims.host_device_id.clone(),
        host.public_key(),
        1_000_000,
        1,
    )?;
    let authority = NetworkAuthoritySigner::from_master_seed(&[49; 32])?;
    let offline = OfflineGrantBundleClaims {
        bundle_version: 1,
        deployment_id: claims.deployment_id.clone(),
        space_id: id(40),
        bundle_id: id(41),
        policy_epoch: 1,
        security_epoch: 1,
        highest_revocation_epoch: 1,
        issued_at_ms: 1_000_000,
        expires_at_ms: 1_060_000,
        members: [
            OfflineMember {
                installation_id: claims.controller_device_id.clone(),
                account_id: claims.account_id.clone(),
                public_key: controller.public_key(),
                membership_epoch: 1,
                process_nonce: process.nonce(),
            },
            OfflineMember {
                installation_id: claims.host_device_id.clone(),
                account_id: id(42),
                public_key: host.public_key(),
                membership_epoch: 1,
                process_nonce: host_process.nonce(),
            },
        ],
        connection: OfflineConnection {
            connection_id: id(43),
            path_id: id(44),
            direct_transports: vec![OfflineDirectTransport::Quic],
        },
        business: OfflineBusiness::RemoteControl {
            resource_id: claims.resource_id.clone(),
            operations: vec![OfflineRemoteOperation::View],
            capability_digest: [7; 32],
        },
        resources: OfflineResourceReservation {
            reservation_id: id(45),
            byte_limit: 32,
            file_write_limit: 0,
            connection_limit: 2,
        },
    };
    let revoked = std::collections::BTreeSet::new();
    let public = authority.public_key();
    let context = OfflineVerification {
        authority: &public,
        deployment_id: &claims.deployment_id,
        space_id: &offline.space_id,
        policy_epoch: 1,
        security_epoch: 1,
        highest_revocation_epoch: 1,
        revoked_bundle_ids: &revoked,
        now_ms: 1_000_000,
    };
    let digest = offline_draft_digest(&public, &offline)?;
    let admission = process.activate(
        verify_offline_bundle(&authority.sign_offline_bundle(&offline)?, &context)?,
        &context,
        digest,
    )?;
    let owner = nestlink_session::OfflineRemoteAuthority::new(admission)?;
    owner.reserve_attempt(1_016_000, OfflineDirectTransport::Quic)?;
    let now = ClockSample {
        monotonic_ms: 16_000,
        unix_ms: 1_016_000,
    };
    assert!(
        Session::activate_offline(
            verified(&signer, &claims),
            binding.clone(),
            owner.clone(),
            now
        )
        .is_err()
    );
    owner.authenticate(1_016_000, OfflineDirectTransport::Quic, &host.public_key())?;
    assert!(
        Session::activate(
            verified(&signer, &claims),
            binding.clone(),
            Path::Direct,
            16_000,
            now
        )
        .is_err()
    );
    let mut session =
        Session::activate_offline(verified(&signer, &claims), binding, owner.clone(), now)?;
    assert_eq!(session.proof_transcript().permit_sha256, digest);
    assert!(
        session
            .authorize(Permission::View, Path::Direct, 16_000)
            .is_err()
    );
    for (role, key) in [
        (EndpointRole::Controller, &controller),
        (EndpointRole::Host, &host),
    ] {
        let proof = key.prove(&session.proof_transcript())?;
        session.confirm_endpoint(role, &key.public_key(), &proof, 16_000)?;
    }
    session.authorize(Permission::View, Path::Direct, 16_000)?;
    assert!(
        session
            .authorize(Permission::Input, Path::Direct, 16_000)
            .is_err()
    );
    assert!(
        session
            .authorize(Permission::View, Path::Relay, 16_000)
            .is_err()
    );
    assert!(session.current_input_permit(Path::Direct, 16_000).is_err());
    assert!(
        session
            .renew(verified(&signer, &claims), 16_001, now)
            .is_err()
    );
    session.charge_business(Permission::View, Path::Direct, 30, now)?;
    assert_eq!(owner.status()?.remaining_bytes, 2);
    session.stop(StopReason::TransportLost);
    assert!(!owner.status()?.stopped);
    owner.reserve_attempt(1_016_000, OfflineDirectTransport::Quic)?;
    assert_eq!(owner.status()?.connection_attempts, 2);
    assert_eq!(owner.status()?.remaining_bytes, 2);
    process.stop();
    assert!(owner.check(1_016_001).is_err());
    Ok(())
}

#[test]
fn ice_path_selection_preserves_deadline_and_invalidates_the_old_challenge() {
    let (signer, controller, _, mut claims, mut binding) = fixture();
    claims.paths.push(Path::Relay as i32);
    binding.local_paths = PathSet::BOTH;
    let mut session = activate(&signer, &claims, binding);
    let deadline = session.deadline_ms();
    let old_proof = session.proof_transcript();
    let old_signature = controller.prove(&old_proof).unwrap();
    session
        .select_path_before_proof(
            Path::Relay,
            ClockSample {
                monotonic_ms: 1200,
                unix_ms: 1_000_200,
            },
        )
        .unwrap();
    assert_eq!(session.deadline_ms(), deadline);
    assert_eq!(session.proof_transcript().path, Path::Relay as i32);
    assert_ne!(session.proof_transcript().challenge, old_proof.challenge);
    assert!(
        session
            .confirm_endpoint(
                EndpointRole::Controller,
                &controller.public_key(),
                &old_signature,
                1200
            )
            .is_err()
    );
    let selected = session.proof_transcript();
    session
        .select_path_before_proof(
            Path::Relay,
            ClockSample {
                monotonic_ms: 1201,
                unix_ms: 1_000_201,
            },
        )
        .unwrap();
    assert_eq!(session.proof_transcript(), selected);
    assert!(
        session
            .select_path_before_proof(
                Path::Direct,
                ClockSample {
                    monotonic_ms: deadline,
                    unix_ms: 1_000_300
                }
            )
            .is_err()
    );
    assert_eq!(session.state(), SessionState::Stopped(StopReason::Expired));
}

#[test]
fn ice_cannot_change_path_after_either_role_proves_or_outside_local_policy() {
    let (signer, controller, host, mut claims, mut binding) = fixture();
    let mut direct = activate(&signer, &claims, binding.clone());
    assert!(
        direct
            .select_path_before_proof(
                Path::Relay,
                ClockSample {
                    monotonic_ms: 1100,
                    unix_ms: 1_000_100
                }
            )
            .is_err()
    );
    claims.paths.push(Path::Relay as i32);
    let mut local_direct = activate(&signer, &claims, binding.clone());
    assert!(
        local_direct
            .select_path_before_proof(
                Path::Relay,
                ClockSample {
                    monotonic_ms: 1100,
                    unix_ms: 1_000_100
                }
            )
            .is_err()
    );
    binding.local_paths = PathSet::BOTH;
    for (role, identity) in [
        (EndpointRole::Controller, &controller),
        (EndpointRole::Host, &host),
    ] {
        let mut session = activate(&signer, &claims, binding.clone());
        let transcript = session.proof_transcript();
        session
            .confirm_endpoint(
                role,
                &identity.public_key(),
                &identity.prove(&transcript).unwrap(),
                1100,
            )
            .unwrap();
        assert!(
            session
                .select_path_before_proof(
                    Path::Relay,
                    ClockSample {
                        monotonic_ms: 1101,
                        unix_ms: 1_000_101
                    }
                )
                .is_err()
        );
        assert_eq!(session.proof_transcript(), transcript);
        assert_eq!(session.state(), SessionState::AwaitingProof);
    }
}

#[test]
fn reconnection_requires_retryable_stop_and_preserves_local_cap_and_latest_permit() {
    let (signer, _, _, claims, binding) = fixture();
    let mut session = activate(&signer, &claims, binding.clone());
    session.cap_deadline_ms(1400).unwrap();
    session.cap_deadline_ms(10000).unwrap();
    assert_eq!(session.deadline_ms(), 1400);
    session.stop(StopReason::TransportLost);
    assert_eq!(
        session
            .reconnection_permit(ClockSample {
                monotonic_ms: 1399,
                unix_ms: 1_000_100
            })
            .unwrap()
            .claims(),
        &claims
    );
    for now in [
        ClockSample {
            monotonic_ms: 1400,
            unix_ms: 1_000_100,
        },
        ClockSample {
            monotonic_ms: 999,
            unix_ms: 1_000_100,
        },
        ClockSample {
            monotonic_ms: 1100,
            unix_ms: 999_999,
        },
        ClockSample {
            monotonic_ms: 1100,
            unix_ms: 1_015_000,
        },
    ] {
        assert!(session.reconnection_permit(now).is_err());
    }
    for reason in [
        StopReason::Revoked,
        StopReason::Expired,
        StopReason::ExplicitExit,
        StopReason::PlatformChanged,
        StopReason::Suspended,
        StopReason::ClockInvalid,
        StopReason::ProtocolViolation,
    ] {
        let mut terminal = activate(&signer, &claims, binding.clone());
        terminal.stop(reason);
        assert!(
            terminal
                .reconnection_permit(ClockSample {
                    monotonic_ms: 1100,
                    unix_ms: 1_000_100
                })
                .is_err()
        );
    }
    let mut renewed = activate(&signer, &claims, binding);
    let mut next = claims.clone();
    next.lease_sequence += 1;
    next.issued_at_unix_ms += 100;
    next.expires_at_unix_ms += 100;
    renewed
        .renew(
            verified(&signer, &next),
            1100,
            ClockSample {
                monotonic_ms: 1100,
                unix_ms: 1_000_100,
            },
        )
        .unwrap();
    renewed.stop(StopReason::NetworkChanged);
    assert_eq!(
        renewed
            .reconnection_permit(ClockSample {
                monotonic_ms: 1200,
                unix_ms: 1_000_200
            })
            .unwrap()
            .claims(),
        &next
    );
}
fn prove(
    session: &mut Session,
    controller: &InstallationIdentity,
    host: &InstallationIdentity,
    now: u64,
) {
    let transcript = session.proof_transcript();
    session
        .confirm_endpoint(
            EndpointRole::Controller,
            &controller.public_key(),
            &controller.prove(&transcript).unwrap(),
            now,
        )
        .unwrap();
    session
        .confirm_endpoint(
            EndpointRole::Host,
            &host.public_key(),
            &host.prove(&transcript).unwrap(),
            now,
        )
        .unwrap();
}

#[test]
fn setup_authorizes_only_proof_until_a_running_permit_is_accepted() {
    let (signer, controller, host, mut claims, mut binding) = fixture();
    let feature = nestlink_protocol::ice::SETUP_CAPABILITY.to_owned();
    claims.required_capabilities.push(feature.clone());
    binding.supported_capabilities.push(feature);
    claims.expires_at_unix_ms = claims.issued_at_unix_ms + 30_000;
    let mut session = activate(&signer, &claims, binding);
    prove(&mut session, &controller, &host, 1000);
    assert_eq!(session.state(), SessionState::Active);
    for permission in [Permission::View, Permission::Input, Permission::FileRead] {
        assert_eq!(
            session
                .authorize(permission, Path::Direct, 1100)
                .unwrap_err()
                .code,
            ErrorCode::AuthRequired
        );
    }
    let mut running = claims.clone();
    running.lease_sequence = 2;
    running.issued_at_unix_ms += 100;
    // A setup feature on a later sequence must not extend running leases.
    assert!(running.validate().is_err());
    running.expires_at_unix_ms = running.issued_at_unix_ms + 15_000;
    session
        .renew(
            verified(&signer, &running),
            1100,
            ClockSample {
                monotonic_ms: 1100,
                unix_ms: 1_000_100,
            },
        )
        .unwrap();
    session
        .authorize(Permission::View, Path::Direct, 1101)
        .unwrap();
    session
        .authorize(Permission::Input, Path::Direct, 1101)
        .unwrap();
}

#[test]
fn both_endpoint_keys_are_required_and_channel_permissions_stay_separate() {
    let (signer, controller, host, claims, binding) = fixture();
    let mut session = activate(&signer, &claims, binding);
    assert_eq!(
        session
            .authorize(Permission::View, Path::Direct, 1000)
            .unwrap_err()
            .code,
        ErrorCode::AuthRequired
    );
    prove(&mut session, &controller, &host, 1000);
    assert_eq!(session.state(), SessionState::Active);
    assert!(
        session
            .authorize(Permission::Input, Path::Direct, 1100)
            .is_ok()
    );
    assert_eq!(
        session
            .authorize(Permission::FileWrite, Path::Direct, 1100)
            .unwrap_err()
            .code,
        ErrorCode::PermissionRequired
    );
    assert!(
        session
            .authorize(Permission::View, Path::Relay, 1100)
            .is_err()
    );
}

#[test]
fn tampering_wrong_issuer_and_signature_purpose_are_rejected() {
    let (signer, controller, _, claims, _) = fixture();
    let signed = signer.sign(&claims).unwrap();
    assert!(
        verify_permit(
            &signed.encode_to_vec(),
            &PermitSigner::from_seed([8; 32]).public_key()
        )
        .is_err()
    );
    let mut tampered = signed.clone();
    tampered.claims[0] ^= 1;
    assert!(verify_permit(&tampered.encode_to_vec(), &signer.public_key()).is_err());
    let mut session = activate(&signer, &claims, fixture().4);
    let proof = controller.prove(&session.proof_transcript()).unwrap();
    let forged = SignedPermit {
        claims: signed.claims,
        signature: proof,
    };
    assert!(verify_permit(&forged.encode_to_vec(), &controller.public_key()).is_err());
    assert!(
        session
            .confirm_endpoint(
                EndpointRole::Host,
                &controller.public_key(),
                &forged.signature,
                1000
            )
            .is_err()
    );
}

#[test]
fn proof_replay_and_path_or_generation_changes_are_rejected() {
    let (signer, controller, _, claims, binding) = fixture();
    let mut first = activate(&signer, &claims, binding.clone());
    let proof = controller.prove(&first.proof_transcript()).unwrap();
    first
        .confirm_endpoint(
            EndpointRole::Controller,
            &controller.public_key(),
            &proof,
            1000,
        )
        .unwrap();
    assert_eq!(
        first
            .confirm_endpoint(
                EndpointRole::Controller,
                &controller.public_key(),
                &proof,
                1000
            )
            .unwrap_err()
            .code,
        ErrorCode::ReplayRejected
    );
    let mut second = activate(&signer, &claims, binding);
    assert!(
        second
            .confirm_endpoint(
                EndpointRole::Controller,
                &controller.public_key(),
                &proof,
                1000
            )
            .is_err()
    );
}

#[test]
fn every_identity_generation_and_resource_binding_is_enforced() {
    let (signer, _, _, claims, binding) = fixture();
    let mut mutations = Vec::new();
    macro_rules! changed {
        ($field:ident,$value:expr) => {{
            let mut b = binding.clone();
            b.$field = $value;
            mutations.push(b);
        }};
    }
    changed!(deployment_id, id(9));
    changed!(security_epoch, 2);
    changed!(session_id, id(9));
    changed!(account_id, id(9));
    changed!(controller_device_id, id(9));
    changed!(host_device_id, id(9));
    changed!(resource_id, id(9));
    changed!(policy_revision, 2);
    changed!(connection_generation, 2);
    changed!(controller_key_sha256, [8; 32]);
    changed!(host_key_sha256, [8; 32]);
    changed!(capability_sha256, [8; 32]);
    for b in mutations {
        assert!(
            Session::activate(
                verified(&signer, &claims),
                b,
                Path::Direct,
                1000,
                ClockSample {
                    monotonic_ms: 1000,
                    unix_ms: 1_000_000
                }
            )
            .is_err()
        );
    }
}

#[test]
fn unknown_required_capabilities_invalid_permissions_and_schema_are_rejected() {
    let (signer, _, _, mut claims, binding) = fixture();
    claims.required_capabilities.push("future-required".into());
    assert!(
        Session::activate(
            verified(&signer, &claims),
            binding,
            Path::Direct,
            1000,
            ClockSample {
                monotonic_ms: 1000,
                unix_ms: 1_000_000
            }
        )
        .is_err()
    );
    claims.permissions.push(999);
    assert!(signer.sign(&claims).is_err());
    claims.permissions.pop();
    claims.paths.push(Path::Direct as i32);
    assert!(signer.sign(&claims).is_err());
    claims.paths.pop();
    claims.schema_version = 14;
    assert!(signer.sign(&claims).is_err());
}

#[test]
fn renewal_is_monotonic_and_old_or_reordered_responses_never_extend_lease() {
    let (signer, controller, host, mut claims, binding) = fixture();
    let mut session = activate(&signer, &claims, binding);
    prove(&mut session, &controller, &host, 1000);
    let old = verified(&signer, &claims);
    claims.lease_sequence = 2;
    claims.issued_at_unix_ms += 5000;
    claims.expires_at_unix_ms += 5000;
    session
        .renew(
            verified(&signer, &claims),
            6000,
            ClockSample {
                monotonic_ms: 6100,
                unix_ms: 1_005_100,
            },
        )
        .unwrap();
    assert_eq!(session.deadline_ms(), 20900);
    assert_eq!(
        session
            .renew(
                old,
                6200,
                ClockSample {
                    monotonic_ms: 6300,
                    unix_ms: 1_005_300
                }
            )
            .unwrap_err()
            .code,
        ErrorCode::ReplayRejected
    );
    assert_eq!(session.deadline_ms(), 20900);
}

#[test]
fn business_renewal_preserves_a_separate_nonrenewable_route_deadline() {
    let (signer, controller, host, mut claims, binding) = fixture();
    let mut session = activate(&signer, &claims, binding);
    prove(&mut session, &controller, &host, 1000);
    session.cap_lifetime_deadline_ms(8000).unwrap();
    session.cap_lifetime_deadline_ms(9000).unwrap();
    claims.lease_sequence = 2;
    claims.issued_at_unix_ms += 5000;
    claims.expires_at_unix_ms += 5000;
    session
        .renew(
            verified(&signer, &claims),
            6000,
            ClockSample {
                monotonic_ms: 6100,
                unix_ms: 1_005_100,
            },
        )
        .unwrap();
    assert_eq!(session.deadline_ms(), 8000);
    assert!(
        session
            .authorize(Permission::View, Path::Direct, 7999)
            .is_ok()
    );
    assert_eq!(
        session
            .authorize(Permission::View, Path::Direct, 8000)
            .unwrap_err()
            .code,
        ErrorCode::LeaseExpired
    );
    assert_eq!(session.state(), SessionState::Stopped(StopReason::Expired));
}

#[test]
fn delayed_response_clock_rollback_and_expiry_cannot_restart_lifetime() {
    let (signer, _, _, mut claims, binding) = fixture();
    assert!(
        Session::activate(
            verified(&signer, &claims),
            binding.clone(),
            Path::Direct,
            1000,
            ClockSample {
                monotonic_ms: 17000,
                unix_ms: 1_000_000
            }
        )
        .is_err()
    );
    let mut session = activate(&signer, &claims, binding.clone());
    assert!(session.check_live(16000).is_err());
    claims.lease_sequence = 2;
    claims.issued_at_unix_ms += 5000;
    claims.expires_at_unix_ms += 5000;
    assert!(
        session
            .renew(
                verified(&signer, &claims),
                16000,
                ClockSample {
                    monotonic_ms: 16001,
                    unix_ms: 1_005_000
                }
            )
            .is_err()
    );
    let mut rollback = activate(&signer, &fixture().3, binding);
    assert!(
        rollback
            .renew(
                verified(&signer, &claims),
                6000,
                ClockSample {
                    monotonic_ms: 6100,
                    unix_ms: 999_999
                }
            )
            .is_err()
    );
    assert_eq!(
        rollback.state(),
        SessionState::Stopped(StopReason::ClockInvalid)
    );
}

#[test]
fn revocation_suspend_network_change_and_exit_are_terminal_with_cleanup_effects() {
    for reason in [
        StopReason::Revoked,
        StopReason::Suspended,
        StopReason::NetworkChanged,
        StopReason::ExplicitExit,
    ] {
        let (signer, controller, host, mut claims, binding) = fixture();
        let mut session = activate(&signer, &claims, binding);
        prove(&mut session, &controller, &host, 1000);
        let effects = session.stop(reason);
        assert!(
            effects.cancel_channels
                && effects.release_inputs
                && effects.discard_queues
                && effects.close_allocations
        );
        assert!(
            session
                .authorize(Permission::Input, Path::Direct, 1100)
                .is_err()
        );
        claims.lease_sequence = 2;
        assert!(
            session
                .renew(
                    verified(&signer, &claims),
                    1100,
                    ClockSample {
                        monotonic_ms: 1200,
                        unix_ms: 1_000_200
                    }
                )
                .is_err()
        );
        assert_eq!(session.state(), SessionState::Stopped(reason));
    }
}

#[test]
fn idle_clock_observations_detect_rollback_before_any_renewal() {
    let (signer, controller, host, claims, binding) = fixture();
    let mut session = activate(&signer, &claims, binding);
    prove(&mut session, &controller, &host, 1000);
    session
        .check_clock(ClockSample {
            monotonic_ms: 1100,
            unix_ms: 1_000_100,
        })
        .unwrap();
    assert!(
        session
            .check_clock(ClockSample {
                monotonic_ms: 1200,
                unix_ms: 1_000_050
            })
            .is_err()
    );
    assert_eq!(
        session.state(),
        SessionState::Stopped(StopReason::ClockInvalid)
    );
    assert!(
        session
            .check_clock(ClockSample {
                monotonic_ms: 1300,
                unix_ms: 1_000_300
            })
            .is_err()
    );
}

#[test]
fn proof_activation_after_transport_setup_keeps_the_original_deadline() {
    let (signer, _, _, claims, binding) = fixture();
    let now = ClockSample {
        monotonic_ms: 10_000,
        unix_ms: 1_009_000,
    };
    // Nine seconds of transport setup used to be subtracted twice, even
    // though six seconds remained in the already retained authorization.
    let old = Session::activate(
        verified(&signer, &claims),
        binding.clone(),
        Path::Direct,
        1_000,
        now,
    )
    .err()
    .unwrap();
    assert_eq!(old.code, ErrorCode::LeaseExpired);
    assert_eq!(old.reason, "lease response arrived too late");

    let mut session = Session::activate_with_retained_deadline(
        verified(&signer, &claims),
        binding,
        Path::Direct,
        now,
        16_000,
    )
    .unwrap();
    assert_eq!(session.state(), SessionState::AwaitingProof);
    assert_eq!(session.deadline_ms(), 16_000);
    assert!(session.check_live(15_999).is_ok());
    assert!(session.check_live(16_000).is_err());
    assert_eq!(session.state(), SessionState::Stopped(StopReason::Expired));
}

#[test]
fn proof_activation_respects_the_earlier_endpoint_cap_and_rejects_expiry() {
    let (signer, _, _, claims, binding) = fixture();
    let now = ClockSample {
        monotonic_ms: 10_000,
        unix_ms: 1_009_000,
    };
    let mut session = Session::activate_with_retained_deadline(
        verified(&signer, &claims),
        binding.clone(),
        Path::Direct,
        now,
        13_000,
    )
    .unwrap();
    assert_eq!(session.deadline_ms(), 13_000);
    assert!(session.check_live(12_999).is_ok());
    assert!(session.check_live(13_000).is_err());

    let later_cap = Session::activate_with_retained_deadline(
        verified(&signer, &claims),
        binding.clone(),
        Path::Direct,
        now,
        20_000,
    )
    .unwrap();
    assert_eq!(later_cap.deadline_ms(), 16_000);

    for expired_cap in [9_999, 10_000] {
        assert!(
            Session::activate_with_retained_deadline(
                verified(&signer, &claims),
                binding.clone(),
                Path::Direct,
                now,
                expired_cap,
            )
            .is_err()
        );
    }
    assert!(
        Session::activate_with_retained_deadline(
            verified(&signer, &claims),
            binding,
            Path::Direct,
            ClockSample {
                monotonic_ms: 16_000,
                unix_ms: claims.expires_at_unix_ms,
            },
            20_000,
        )
        .is_err()
    );
}

#[test]
fn proof_activation_does_not_revive_a_session_after_clock_regression() {
    let (signer, _, _, claims, binding) = fixture();
    let now = ClockSample {
        monotonic_ms: 10_000,
        unix_ms: 1_009_000,
    };
    for regressed in [
        ClockSample {
            monotonic_ms: 9_999,
            unix_ms: 1_009_001,
        },
        ClockSample {
            monotonic_ms: 10_001,
            unix_ms: 1_008_999,
        },
    ] {
        let mut session = Session::activate_with_retained_deadline(
            verified(&signer, &claims),
            binding.clone(),
            Path::Direct,
            now,
            16_000,
        )
        .unwrap();
        assert!(session.check_clock(regressed).is_err());
        assert_eq!(
            session.state(),
            SessionState::Stopped(StopReason::ClockInvalid)
        );
        assert!(
            session
                .check_clock(ClockSample {
                    monotonic_ms: 10_002,
                    unix_ms: 1_009_002,
                })
                .is_err()
        );
    }
}

#[test]
fn proof_activation_requires_a_renewal_request_newer_than_activation() {
    let (signer, controller, host, mut claims, binding) = fixture();
    let mut session = Session::activate_with_retained_deadline(
        verified(&signer, &claims),
        binding,
        Path::Direct,
        ClockSample {
            monotonic_ms: 10_000,
            unix_ms: 1_009_000,
        },
        16_000,
    )
    .unwrap();
    let transcript = session.proof_transcript();
    for (role, identity) in [
        (EndpointRole::Controller, controller),
        (EndpointRole::Host, host),
    ] {
        session
            .confirm_endpoint(
                role,
                &identity.public_key(),
                &identity.prove(&transcript).unwrap(),
                10_000,
            )
            .unwrap();
    }
    assert_eq!(session.state(), SessionState::Active);
    claims.lease_sequence += 1;
    claims.issued_at_unix_ms = 1_009_000;
    claims.expires_at_unix_ms = 1_024_000;
    let renewed = verified(&signer, &claims);
    let response_clock = ClockSample {
        monotonic_ms: 10_002,
        unix_ms: 1_009_002,
    };
    for stale_request in [1_000, 9_999, 10_000] {
        let error = session
            .renew(renewed.clone(), stale_request, response_clock)
            .err()
            .unwrap();
        assert_eq!(error.code, ErrorCode::ReplayRejected);
        assert_eq!(session.deadline_ms(), 16_000);
    }
    assert!(session.renew(renewed, 10_001, response_clock).is_ok());
}

#[test]
fn local_media_binding_refresh_requires_advanced_probe_and_preserves_signed_scope()
-> Result<(), Box<dyn std::error::Error>> {
    use nestlink_protocol::media_authority::{
        FORMAT_CAPABILITY, FrozenMediaScope, MediaAnnouncement, MediaDirection, ProbeIdentity,
    };
    use nestlink_protocol::media_format::{FormatSet, FrameRate, VideoFormat};
    use nestlink_session::MediaSessionBinding;
    let (signer, _, _, mut claims, mut binding) = fixture();
    let format = VideoFormat::legacy_h264(31, 320, 240, FrameRate::new(30, 1)?, 2000)?;
    let set = FormatSet::new(vec![format])?;
    claims.required_capabilities = vec![FORMAT_CAPABILITY.into()];
    claims.media_format_version = 2;
    claims.media_formats = vec![format.encode()?];
    claims.media_format_sha256 = set.digest().to_vec();
    let permit = verified(&signer, &claims);
    let frozen = FrozenMediaScope {
        version: 2,
        controller_revision: 1,
        host_revision: 2,
        formats: claims.media_formats.clone(),
        sha256: claims.media_format_sha256.clone(),
    };
    // Synthetic data exercises contract validation; it is not a live owner.
    let mut local = MediaAnnouncement {
        version: 2,
        device_id: claims.host_device_id.clone(),
        direction: MediaDirection::Encode,
        revision: 2,
        expires_at_unix_ms: 1_010_000,
        probe: ProbeIdentity {
            generation: 1,
            resource_id: id(8),
            backend: "cpu-software".into(),
            adapter_luid: None,
            driver_version: None,
        },
        formats: claims.media_formats.clone(),
    };
    let data = MediaSessionBinding::from_local_announcement(
        &permit,
        &frozen,
        &local,
        EndpointRole::Host,
        1_000_000,
    )?;
    assert_eq!(data.backend(), "cpu-software");
    assert_eq!(data.local_direction(), MediaDirection::Encode);
    assert!(
        MediaSessionBinding::from_local_announcement(
            &permit,
            &frozen,
            &local,
            EndpointRole::Controller,
            1_000_000
        )
        .is_err()
    );
    local.revision = 3;
    local.expires_at_unix_ms = 1_020_000;
    let refreshed = data.refresh_from_local_announcement(
        &permit,
        &frozen,
        &local,
        EndpointRole::Host,
        1_001_000,
    )?;
    assert_eq!(refreshed.expires_at_unix_ms(), 1_020_000);
    local.probe.generation = 2;
    local.probe.resource_id = id(9);
    assert!(
        data.refresh_from_local_announcement(
            &permit,
            &frozen,
            &local,
            EndpointRole::Host,
            1_001_000
        )
        .is_ok()
    );
    local.revision = 2;
    assert!(
        data.refresh_from_local_announcement(
            &permit,
            &frozen,
            &local,
            EndpointRole::Host,
            1_001_000
        )
        .is_err()
    );
    local.probe.generation = 1;
    local.formats.clear();
    assert!(
        data.refresh_from_local_announcement(
            &permit,
            &frozen,
            &local,
            EndpointRole::Host,
            1_001_000
        )
        .is_err()
    );
    binding.media = Some(data);
    binding.supported_capabilities = vec![FORMAT_CAPABILITY.into()];
    assert!(
        Session::activate(
            permit,
            binding,
            Path::Direct,
            1000,
            ClockSample {
                monotonic_ms: 1000,
                unix_ms: 1_000_000
            }
        )
        .is_err()
    );
    Ok(())
}
