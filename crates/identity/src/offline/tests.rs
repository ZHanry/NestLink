use super::*;
use nestlink_protocol::network::GrantClaims;

const NOW: u64 = 1_700_000_000_000;
fn id(value: u16) -> String {
    format!("00000000-0000-4000-8000-{value:012x}")
}
struct Fixture {
    signer: NetworkAuthoritySigner,
    authority: [u8; 32],
    processes: [OfflineProcess; 2],
    claims: OfflineGrantBundleClaims,
    revoked: BTreeSet<String>,
}
impl Fixture {
    fn new() -> Result<Self, ContractError> {
        let signer = NetworkAuthoritySigner::from_master_seed(&[55; 32])?;
        let processes = [
            OfflineProcess::new(id(11), [11; 32], NOW, 4)?,
            OfflineProcess::new(id(12), [12; 32], NOW, 4)?,
        ];
        let members = std::array::from_fn(|index| OfflineMember {
            installation_id: id(11 + index as u16),
            account_id: id(21 + index as u16),
            public_key: [11 + index as u8; 32],
            membership_epoch: 2,
            process_nonce: processes[index].nonce(),
        });
        let claims = OfflineGrantBundleClaims {
            bundle_version: 1,
            deployment_id: id(1),
            space_id: id(2),
            bundle_id: id(3),
            policy_epoch: 2,
            security_epoch: 3,
            highest_revocation_epoch: 4,
            issued_at_ms: NOW,
            expires_at_ms: NOW + 60_000,
            members,
            connection: OfflineConnection {
                connection_id: id(4),
                path_id: id(5),
                direct_transports: vec![OfflineDirectTransport::Quic, OfflineDirectTransport::Tls],
            },
            business: OfflineBusiness::RemoteControl {
                resource_id: id(6),
                operations: vec![
                    OfflineRemoteOperation::View,
                    OfflineRemoteOperation::FileWrite,
                ],
                capability_digest: [19; 32],
            },
            resources: OfflineResourceReservation {
                reservation_id: id(7),
                byte_limit: 100,
                file_write_limit: 20,
                connection_limit: 2,
            },
        };
        Ok(Self {
            authority: signer.public_key(),
            signer,
            processes,
            claims,
            revoked: BTreeSet::new(),
        })
    }
    fn context(&self) -> OfflineVerification<'_> {
        OfflineVerification {
            authority: &self.authority,
            deployment_id: &self.claims.deployment_id,
            space_id: &self.claims.space_id,
            policy_epoch: 2,
            security_epoch: 3,
            highest_revocation_epoch: 4,
            revoked_bundle_ids: &self.revoked,
            now_ms: NOW,
        }
    }
    fn verified(&self) -> Result<VerifiedOfflineGrantBundle, ContractError> {
        verify_offline_bundle(
            &self.signer.sign_offline_bundle(&self.claims)?,
            &self.context(),
        )
    }
    fn activate(&mut self) -> Result<OfflineAdmission, ContractError> {
        let bundle = self.verified()?;
        let approved = bundle.digest();
        let authority = self.authority;
        let deployment = self.claims.deployment_id.clone();
        let space = self.claims.space_id.clone();
        let context = OfflineVerification {
            authority: &authority,
            deployment_id: &deployment,
            space_id: &space,
            policy_epoch: 2,
            security_epoch: 3,
            highest_revocation_epoch: 4,
            revoked_bundle_ids: &self.revoked,
            now_ms: NOW,
        };
        self.processes[0].activate(bundle, &context, approved)
    }
}

#[test]
fn complete_chain_is_independent_and_unknown_or_missing_sections_fail()
-> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let signed = f.signer.sign_offline_bundle(&f.claims)?;
    verify_offline_bundle(&signed, &f.context())?;
    assert!(
        GrantClaims::decode_canonical(&signed.claims).is_err(),
        "no legacy online authority is manufactured"
    );
    for section in ["members", "connection", "business", "resources"] {
        let mut value = serde_json::to_value(&f.claims)?;
        value
            .as_object_mut()
            .ok_or("bundle object missing")?
            .remove(section);
        assert!(OfflineGrantBundleClaims::decode_canonical(&serde_json::to_vec(&value)?).is_err());
    }
    let mut value = serde_json::to_value(&f.claims)?;
    value["connection"]["relays"] = serde_json::json!([id(99)]);
    assert!(OfflineGrantBundleClaims::decode_canonical(&serde_json::to_vec(&value)?).is_err());
    let mut tampered = signed.clone();
    tampered.signature[0] ^= 1;
    assert!(verify_offline_bundle(&tampered, &f.context()).is_err());
    let mut wrong_domain = signed;
    let bytes = domain_message(b"NestLink/network/v1/grant\0", &wrong_domain.claims);
    wrong_domain.signature = f.signer.key.sign(&bytes).to_bytes().to_vec();
    assert!(verify_offline_bundle(&wrong_domain, &f.context()).is_err());
    Ok(())
}

#[test]
fn independent_offline_deadline_and_explicit_operations_cannot_expand()
-> Result<(), Box<dyn std::error::Error>> {
    let mut f = Fixture::new()?;
    f.claims.expires_at_ms = NOW + MAX_OFFLINE_MS;
    f.claims.validate()?;
    f.claims.expires_at_ms += 1;
    assert!(f.claims.validate().is_err());
    f.claims.expires_at_ms = NOW + 60_000;
    f.claims
        .connection
        .direct_transports
        .push(OfflineDirectTransport::Quic);
    assert!(f.claims.validate().is_err());
    f.claims.connection.direct_transports.pop();
    f.claims.business = OfflineBusiness::RemoteControl {
        resource_id: id(6),
        operations: vec![OfflineRemoteOperation::View],
        capability_digest: [19; 32],
    };
    assert!(
        f.claims.validate().is_err(),
        "file budget requires explicit FileWrite"
    );
    f.claims.resources.file_write_limit = 0;
    let mut owner = f.activate()?;
    assert!(
        owner
            .admit_remote_operation(NOW, OfflineRemoteOperation::View, 1)
            .is_err()
    );
    assert!(
        owner
            .admit_connection(NOW, OfflineDirectTransport::Quic, &[99; 32])
            .is_err()
    );
    owner.admit_connection(NOW, OfflineDirectTransport::Quic, &[12; 32])?;
    owner.admit_remote_operation(NOW, OfflineRemoteOperation::View, 1)?;
    assert!(
        owner
            .admit_remote_operation(NOW, OfflineRemoteOperation::Input, 1)
            .is_err()
    );
    assert!(
        owner
            .admit_remote_operation(NOW, OfflineRemoteOperation::FileWrite, 1)
            .is_err()
    );
    assert!(
        owner
            .admit_private_service(NOW, &[1; 32], &[2; 32], 1)
            .is_err()
    );
    assert_eq!(owner.spent_bytes(), 1);
    Ok(())
}

#[test]
fn original_process_activation_and_cumulative_budget_survive_reconnect_only()
-> Result<(), Box<dyn std::error::Error>> {
    let mut f = Fixture::new()?;
    let mut owner = f.activate()?;
    assert!(
        f.activate().is_err(),
        "a second entry point cannot reset this reservation"
    );
    owner.admit_connection(NOW, OfflineDirectTransport::Quic, &[12; 32])?;
    owner.admit_remote_operation(NOW, OfflineRemoteOperation::View, 60)?;
    owner.admit_remote_operation(NOW, OfflineRemoteOperation::FileWrite, 20)?;
    owner.admit_connection(NOW + 1, OfflineDirectTransport::Tls, &[12; 32])?;
    assert_eq!(owner.spent_bytes(), 80);
    assert_eq!(owner.written_bytes(), 20);
    owner.admit_remote_operation(NOW + 1, OfflineRemoteOperation::View, 20)?;
    assert!(
        owner
            .admit_remote_operation(NOW + 1, OfflineRemoteOperation::FileWrite, 1)
            .is_err()
    );
    assert!(owner.is_stopped());
    assert_eq!(owner.spent_bytes(), 100);
    assert!(
        owner
            .admit_connection(NOW + 1, OfflineDirectTransport::Quic, &[12; 32])
            .is_err()
    );
    let restored = f.verified()?;
    let approval = restored.digest();
    let mut restarted = OfflineProcess::new(id(11), [11; 32], NOW, 4)?;
    assert!(
        restarted
            .activate(restored, &f.context(), approval)
            .is_err(),
        "old backup cannot reproduce a memory-only process nonce"
    );
    Ok(())
}

#[test]
fn rollback_deadline_and_local_exit_are_terminal_for_existing_owners()
-> Result<(), Box<dyn std::error::Error>> {
    for mode in 0..5 {
        let mut f = Fixture::new()?;
        let mut owner = f.activate()?;
        owner.admit_connection(NOW, OfflineDirectTransport::Quic, &[12; 32])?;
        match mode {
            0 => {
                owner.check_current(NOW + 5)?;
                assert!(owner.check_current(NOW + 4).is_err());
            }
            1 => assert!(owner.check_current(NOW + 60_000).is_err()),
            2 => {
                owner.deadline = Instant::now();
                assert!(owner.check_current(NOW).is_err());
            }
            3 => f.processes[0].stop_handle().stop(),
            _ => drop(f.processes),
        }
        assert!(
            owner
                .admit_remote_operation(NOW + 6, OfflineRemoteOperation::View, 1)
                .is_err()
        );
        assert!(owner.check_current(NOW).is_err());
        assert!(owner.is_stopped());
    }
    Ok(())
}

#[test]
fn recovery_synchronizes_highest_revocation_and_cannot_revive_old_authority()
-> Result<(), Box<dyn std::error::Error>> {
    for mode in 0..5 {
        let mut f = Fixture::new()?;
        let mut owner = f.activate()?;
        let mut context = f.context();
        match mode {
            0 => context.highest_revocation_epoch += 1,
            1 => context.highest_revocation_epoch -= 1,
            2 => context.security_epoch += 1,
            3 => context.policy_epoch += 1,
            _ => context.space_id = "00000000-0000-4000-8000-000000000099",
        }
        assert!(owner.observe_online(&context).is_err());
        assert!(owner.observe_online(&f.context()).is_err());
    }
    let mut f = Fixture::new()?;
    let mut owner = f.activate()?;
    f.revoked.insert(f.claims.bundle_id.clone());
    assert!(owner.observe_online(&f.context()).is_err());
    f.revoked.clear();
    assert!(owner.observe_online(&f.context()).is_err());
    Ok(())
}

#[test]
fn private_service_pins_original_target_and_has_no_remote_rights()
-> Result<(), Box<dyn std::error::Error>> {
    let mut f = Fixture::new()?;
    f.claims.business = OfflineBusiness::PrivateService {
        service_id: id(30),
        service_revision: 2,
        definition_digest: [31; 32],
        target_digest: [32; 32],
    };
    f.claims.resources.file_write_limit = 0;
    let mut owner = f.activate()?;
    owner.admit_connection(NOW, OfflineDirectTransport::Tls, &[12; 32])?;
    assert!(
        owner
            .admit_remote_operation(NOW, OfflineRemoteOperation::View, 1)
            .is_err()
    );
    assert!(
        owner
            .admit_private_service(NOW, &[31; 32], &[33; 32], 10)
            .is_err()
    );
    owner.admit_private_service(NOW, &[31; 32], &[32; 32], 10)?;
    assert_eq!(owner.spent_bytes(), 10);
    owner.admit_connection(NOW, OfflineDirectTransport::Tls, &[12; 32])?;
    assert!(
        owner
            .admit_connection(NOW, OfflineDirectTransport::Tls, &[12; 32])
            .is_err()
    );
    assert!(
        owner
            .admit_private_service(NOW, &[31; 32], &[32; 32], 1)
            .is_err()
    );
    Ok(())
}

#[test]
fn both_endpoint_approvals_bind_the_complete_budget_process_and_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let mut f = Fixture::new()?;
    let source = crate::InstallationIdentity::from_seed([11; 32]);
    let target = crate::InstallationIdentity::from_seed([12; 32]);
    f.claims.members[0].public_key = source.public_key();
    f.claims.members[1].public_key = target.public_key();
    let selected = offline_draft_digest(&f.authority, &f.claims)?;
    let approvals = [
        source.sign_offline_endpoint_approval(&f.authority, &f.claims, 0, selected)?,
        target.sign_offline_endpoint_approval(&f.authority, &f.claims, 1, selected)?,
    ];
    verify_offline_endpoint_approvals(&f.authority, &f.claims, &approvals)?;
    assert!(
        source
            .sign_offline_endpoint_approval(&f.authority, &f.claims, 1, selected)
            .is_err()
    );
    assert!(
        source
            .sign_offline_endpoint_approval(&f.authority, &f.claims, 0, [9; 32])
            .is_err()
    );
    assert!(
        verify_offline_endpoint_approvals(
            &f.authority,
            &f.claims,
            &[approvals[0].clone(), approvals[0].clone()]
        )
        .is_err()
    );
    assert!(verify_offline_endpoint_approvals(&[9; 32], &f.claims, &approvals).is_err());
    let mut increased = f.claims.clone();
    increased.resources.byte_limit += 1;
    assert!(verify_offline_endpoint_approvals(&f.authority, &increased, &approvals).is_err());
    let mut restarted = f.claims.clone();
    restarted.members[0].process_nonce[0] ^= 1;
    assert!(verify_offline_endpoint_approvals(&f.authority, &restarted, &approvals).is_err());
    let mut swapped = approvals.clone();
    swapped.swap(0, 1);
    assert!(verify_offline_endpoint_approvals(&f.authority, &f.claims, &swapped).is_err());
    let binding = channel::OfflineChannelBinding {
        bundle_id: f.claims.bundle_id.clone(),
        draft_digest: selected,
        source_nonce: [21; 32],
        host_nonce: [22; 32],
    };
    let transcript = offline_channel_transcript(&f.claims, selected, &binding, 0)?;
    let signature = source.sign_action(&transcript)?;
    crate::verify_device_action(&transcript, &source.public_key(), &signature)?;
    let wrong_endpoint = offline_channel_transcript(&f.claims, selected, &binding, 1)?;
    assert!(
        crate::verify_device_action(&wrong_endpoint, &source.public_key(), &signature).is_err()
    );
    let mut changed = binding.clone();
    changed.host_nonce[0] ^= 1;
    let changed_proof = offline_channel_transcript(&f.claims, selected, &changed, 0)?;
    assert!(crate::verify_device_action(&changed_proof, &source.public_key(), &signature).is_err());
    changed.source_nonce = [0; 32];
    assert!(offline_channel_transcript(&f.claims, selected, &changed, 0).is_err());
    assert!(offline_channel_transcript(&f.claims, [9; 32], &binding, 0).is_err());
    assert!(offline_channel_transcript(&f.claims, selected, &binding, 2).is_err());
    let consume = offline_consume_transcript(
        &f.claims,
        &management::OfflineConsumeChallenge {
            bundle_id: f.claims.bundle_id.clone(),
            endpoint: 0,
            draft_digest: selected,
            process_nonce: f.claims.members[0].process_nonce,
            challenge: [21; 32],
            expires_at_ms: f.claims.expires_at_ms,
        },
    )?;
    assert!(
        crate::verify_device_action(&consume, &source.public_key(), &signature).is_err(),
        "a live channel proof cannot replay the one-use online consume"
    );
    Ok(())
}
