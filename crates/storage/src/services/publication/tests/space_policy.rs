use super::*;
use nestlink_protocol::{
    network::SpaceRole,
    spaces::{service_publication::*, *},
};

fn bind(f: &mut Fixture) -> Result<SpaceView> {
    let key = nestlink_identity::network::NetworkAuthoritySigner::from_master_seed(&[91; 32])?
        .public_key();
    let space = f.store.create_space(
        &f.creator,
        SpaceCreateRequest {
            name: "Explicit service policy".into(),
        },
        key,
        now()?,
    )?;
    let joined = f.store.join_space_device(
        &f.creator,
        &space.space_id,
        SpaceDeviceJoin {
            expected_revision: space.revision,
            expected_membership_epoch: 0,
            installation_id: f.host_id.clone(),
        },
        now()?,
    )?;
    Ok(f.store.bind_space_service(
        &f.creator,
        &space.space_id,
        &f.view.id,
        SpaceServiceBindingRequest {
            expected_revision: joined.revision,
            expected_service_revision: f.view.revision,
        },
        now()?,
    )?)
}

fn allow(f: &mut Fixture, space: &str, device: bool, deadline: u64) -> Result<SpaceView> {
    let policy = f.store.space_service_policy(&f.creator, space, now()?)?;
    let bound = policy.bindings.first().ok_or("binding missing")?;
    let subject = if device {
        SpaceServiceSubject::Device {
            installation_id: f.host_id.clone(),
        }
    } else {
        SpaceServiceSubject::Account {
            account_id: f.creator.account_id.clone(),
        }
    };
    Ok(f.store.grant_space_service_rule(
        &f.creator,
        space,
        &f.view.id,
        SpaceServiceRuleRequest {
            expected_revision: policy.space.revision,
            expected_binding_epoch: bound.binding_epoch,
            subject,
            protocol: SpaceServiceProtocol::Tcp,
            port: 29100,
            operation: SpaceServiceOperation::Publish,
            expires_at_unix_ms: deadline,
        },
        now()?,
    )?)
}

#[test]
fn bound_services_require_explicit_rules_cap_signed_leases_and_revoke_real_node_resources() -> Result
{
    let mut f = Fixture::new()?;
    let space = bind(&mut f)?;
    assert!(f.publish().is_err());
    let pending = f.store.create_service(
        &f.creator,
        ServiceCreate {
            id: random_id(),
            definition: f.view.definition.clone(),
        },
        now()? / 1000,
    )?;
    assert!(
        f.store
            .bind_space_service(
                &f.creator,
                &space.space_id,
                &pending.id,
                SpaceServiceBindingRequest {
                    expected_revision: space.revision,
                    expected_service_revision: pending.revision
                },
                now()?
            )
            .is_err()
    );
    let deadline = now()? + 5000;
    let permitted = allow(&mut f, &space.space_id, false, deadline)?;
    let publication = f.publish()?;
    assert!(publication.claims.expires_at_unix_ms <= deadline);
    let query = f.query(1)?;
    let snapshot = f.store.service_resource_snapshot(
        &f.life,
        &query,
        &f.service_signer,
        now()?,
        |_| Ok(()),
    )?;
    assert_eq!(snapshot.leases.len(), 1);
    let policy = f
        .store
        .space_service_policy(&f.creator, &space.space_id, now()?)?;
    let rule = &policy.bindings[0].rules[0].rule_id;
    f.store.revoke_space_service_rule(
        &f.creator,
        &space.space_id,
        &f.view.id,
        rule,
        SpaceRevisionRequest {
            expected_revision: permitted.revision,
        },
        now()?,
    )?;
    assert!(
        f.store
            .service_publication(&f.life, &f.creator, &f.view.id, now()?)
            .is_err()
    );
    let query = f.query(2)?;
    let snapshot = f.store.service_resource_snapshot(
        &f.life,
        &query,
        &f.service_signer,
        now()?,
        |_| Ok(()),
    )?;
    assert!(snapshot.leases.is_empty());
    let (state, promise): (u64, u64) = f.store.connection.query_row(
        "SELECT state,promised_until FROM service_publications WHERE id=?1",
        [&publication.claims.publication_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    assert_eq!(state, 1);
    assert!(promise > publication.claims.expires_at_unix_ms);
    let active_budget: bool = f.store.connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM service_usage_grants WHERE publication_id=?1 AND terminal=0)",
        [&publication.claims.publication_id],
        |r| r.get(0),
    )?;
    assert!(active_budget);
    Ok(())
}

#[test]
fn device_rules_are_exact_and_removal_rejoin_archive_and_revoked_binding_fail_closed() -> Result {
    let mut f = Fixture::new()?;
    let space = bind(&mut f)?;
    let policy = f
        .store
        .space_service_policy(&f.creator, &space.space_id, now()?)?;
    let request_deadline = now()? + 60_000;
    let request = |subject, protocol, port| SpaceServiceRuleRequest {
        expected_revision: space.revision,
        expected_binding_epoch: policy.bindings[0].binding_epoch,
        subject,
        protocol,
        port,
        operation: SpaceServiceOperation::Publish,
        expires_at_unix_ms: request_deadline,
    };
    assert!(
        f.store
            .grant_space_service_rule(
                &f.creator,
                &space.space_id,
                &f.view.id,
                request(
                    SpaceServiceSubject::Device {
                        installation_id: random_id()
                    },
                    SpaceServiceProtocol::Tcp,
                    29100
                ),
                now()?
            )
            .is_err()
    );
    assert!(
        f.store
            .grant_space_service_rule(
                &f.creator,
                &space.space_id,
                &f.view.id,
                request(
                    SpaceServiceSubject::Device {
                        installation_id: f.host_id.clone()
                    },
                    SpaceServiceProtocol::Udp,
                    29100
                ),
                now()?
            )
            .is_err()
    );
    assert!(
        f.store
            .grant_space_service_rule(
                &f.creator,
                &space.space_id,
                &f.view.id,
                request(
                    SpaceServiceSubject::Device {
                        installation_id: f.host_id.clone()
                    },
                    SpaceServiceProtocol::Tcp,
                    29101
                ),
                now()?
            )
            .is_err()
    );
    let permitted = allow(&mut f, &space.space_id, true, now()? + 60_000)?;
    f.publish()?;
    let removed = f.store.remove_space_device(
        &f.creator,
        &space.space_id,
        &f.host_id,
        SpaceDeviceRemoval {
            expected_revision: permitted.revision,
            expected_membership_epoch: 1,
        },
        now()?,
    )?;
    assert!(
        f.store
            .space_service_publication_deadline(
                &f.view.id,
                f.view.revision,
                &f.creator.account_id,
                &f.view.definition,
                now()?
            )
            .is_err()
    );
    let joined = f.store.join_space_device(
        &f.creator,
        &space.space_id,
        SpaceDeviceJoin {
            expected_revision: removed.revision,
            expected_membership_epoch: 2,
            installation_id: f.host_id.clone(),
        },
        now()?,
    )?;
    assert!(
        f.store
            .space_service_publication_deadline(
                &f.view.id,
                f.view.revision,
                &f.creator.account_id,
                &f.view.definition,
                now()?
            )
            .is_err()
    );
    let allowed = allow(&mut f, &space.space_id, true, now()? + 60_000)?;
    assert!(
        f.store
            .space_service_publication_deadline(
                &f.view.id,
                f.view.revision,
                &f.creator.account_id,
                &f.view.definition,
                now()?
            )?
            .is_some()
    );
    assert!(allowed.revision > joined.revision);
    let revoked = f.store.revoke_space_service(
        &f.creator,
        &space.space_id,
        &f.view.id,
        SpaceRevisionRequest {
            expected_revision: allowed.revision,
        },
        now()?,
    )?;
    assert!(
        f.store
            .space_service_publication_deadline(
                &f.view.id,
                f.view.revision,
                &f.creator.account_id,
                &f.view.definition,
                now()?
            )
            .is_err()
    );
    let rebound = f.store.bind_space_service(
        &f.creator,
        &space.space_id,
        &f.view.id,
        SpaceServiceBindingRequest {
            expected_revision: revoked.revision,
            expected_service_revision: f.view.revision,
        },
        now()?,
    )?;
    assert!(
        f.store
            .space_service_publication_deadline(
                &f.view.id,
                f.view.revision,
                &f.creator.account_id,
                &f.view.definition,
                now()?
            )
            .is_err()
    );
    let permitted = allow(&mut f, &space.space_id, false, now()? + 60_000)?;
    assert!(permitted.revision > rebound.revision);
    f.store.archive_space(
        &f.creator,
        &space.space_id,
        SpaceRevisionRequest {
            expected_revision: permitted.revision,
        },
        now()?,
    )?;
    assert!(
        f.store
            .space_service_publication_deadline(
                &f.view.id,
                f.view.revision,
                &f.creator.account_id,
                &f.view.definition,
                now()?
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn member_removal_and_rule_expiry_never_revive_service_publication() -> Result {
    let mut f = Fixture::new()?;
    let space = bind(&mut f)?;
    let password = "space-service-manager-password";
    f.store
        .create_member(&f.creator, "space-manager", password)?;
    let manager = f
        .store
        .login(
            "space-manager",
            password,
            None,
            now()? / 1000,
            &VaultKey::from_bytes([62; 32]),
            &hash_password("space-manager-dummy")?,
        )?
        .principal;
    let invitation = f.store.invite_to_space(
        &f.creator,
        &space.space_id,
        SpaceInvitationRequest {
            expected_revision: space.revision,
            role: SpaceRole::Admin,
            target_account_id: Some(manager.account_id.clone()),
            expires_at_unix_ms: now()? + 60_000,
        },
        now()?,
    )?;
    let accepted = f.store.accept_space_invitation(
        &manager,
        &space.space_id,
        &invitation.invitation.invitation_id,
        SpaceInvitationAcceptance {
            token: invitation.token,
        },
        now()?,
    )?;
    let transferred = f.store.update_space_member(
        &f.creator,
        &space.space_id,
        &manager.account_id,
        SpaceMemberUpdate {
            expected_revision: accepted.revision,
            expected_member_epoch: accepted.member_epoch,
            role: SpaceRole::Owner,
        },
        now()?,
    )?;
    let deadline = now()? + 5000;
    let permitted = allow(&mut f, &space.space_id, false, deadline)?;
    f.publish()?;
    assert!(
        f.store
            .space_service_publication_deadline(
                &f.view.id,
                f.view.revision,
                &f.creator.account_id,
                &f.view.definition,
                deadline
            )
            .is_err()
    );
    let removed = f.store.remove_space_member(
        &manager,
        &space.space_id,
        &f.creator.account_id,
        SpaceMemberRemoval {
            expected_revision: permitted.revision,
            expected_member_epoch: transferred.member_epoch,
        },
        now()?,
    )?;
    let invitation = f.store.invite_to_space(
        &manager,
        &space.space_id,
        SpaceInvitationRequest {
            expected_revision: removed.revision,
            role: SpaceRole::Admin,
            target_account_id: Some(f.creator.account_id.clone()),
            expires_at_unix_ms: now()? + 60_000,
        },
        now()?,
    )?;
    let rejoined = f.store.accept_space_invitation(
        &f.creator,
        &space.space_id,
        &invitation.invitation.invitation_id,
        SpaceInvitationAcceptance {
            token: invitation.token,
        },
        now()?,
    )?;
    let device_epoch = f
        .store
        .space_details(&f.creator, &space.space_id, now()?)?
        .devices
        .into_iter()
        .find(|device| device.installation_id == f.host_id)
        .ok_or("host missing")?
        .membership_epoch;
    f.store.join_space_device(
        &f.creator,
        &space.space_id,
        SpaceDeviceJoin {
            expected_revision: rejoined.revision,
            expected_membership_epoch: device_epoch,
            installation_id: f.host_id.clone(),
        },
        now()?,
    )?;
    assert!(
        f.store
            .space_service_publication_deadline(
                &f.view.id,
                f.view.revision,
                &f.creator.account_id,
                &f.view.definition,
                now()?
            )
            .is_err()
    );
    assert!(
        f.store
            .service_publication(&f.life, &f.creator, &f.view.id, now()?)
            .is_err()
    );
    Ok(())
}
