use super::*;
use nestlink_identity::network::remote_preparation_grant_ids;
use nestlink_protocol::{api::NetworkRemotePreparationRequest, spaces::*};
use prost::Message;

struct PreparedFixture {
    store: Store,
    owner: Principal,
    controller: Principal,
    host: Principal,
    signer: NetworkAuthoritySigner,
    space: String,
    request: String,
    binding: NetworkRemotePreparationRequest,
}
impl PreparedFixture {
    fn new(approve: bool) -> Result<Self> {
        let (mut store, vault, dummy, owner, host) = fixture()?;
        store.create_member(&owner, "controller", PASSWORD)?;
        let controller = store.login("controller", PASSWORD, None, NOW / 1000, &vault, &dummy)?.principal;
        let controller_identity = InstallationIdentity::generate();
        let host_identity = InstallationIdentity::generate();
        let cid = enroll(&mut store, &controller, &controller_identity, "controller")?;
        let hid = enroll(&mut store, &host, &host_identity, "host")?;
        let signer = NetworkAuthoritySigner::from_master_seed(&[81; 32])?;
        let space = store.create_space(&owner, SpaceCreateRequest { name: "approved pair".into() }, signer.public_key(), NOW)?.space_id;
        for actor in [&controller, &host] {
            let current = store.space_details(&owner, &space, NOW)?.space;
            let invitation = store.invite_to_space(&owner, &space, SpaceInvitationRequest {
                expected_revision: current.revision, role: SpaceRole::Member,
                target_account_id: Some(actor.account_id.clone()), expires_at_unix_ms: NOW + 60_000,
            }, NOW)?;
            store.accept_space_invitation(actor, &space, &invitation.invitation.invitation_id,
                SpaceInvitationAcceptance { token: invitation.token }, NOW)?;
        }
        for (actor, installation) in [(&controller, &cid), (&host, &hid)] {
            let current = store.space_details(actor, &space, NOW)?.space;
            store.join_space_device(actor, &space, SpaceDeviceJoin {
                expected_revision: current.revision, expected_membership_epoch: 0,
                installation_id: installation.clone(),
            }, NOW)?;
        }
        let request = store.create_remote(&controller, RemoteRequest {
            id: random_id(), controller_device_id: cid, host_device_id: hid,
            permissions: vec![Permission::View as i32], path_mode: "direct_only".into(),
        }, NOW / 1000)?.id;
        let (connection_generation, permit_sha256) = if approve {
            let choice = ApprovalChoice { approved: true, permissions: vec![Permission::View as i32], paths: vec![Path::Direct as i32] };
            let signature = URL_SAFE_NO_PAD.encode(host_identity.sign_action(
                &store.approval_transcript(&host, &request, &choice, NOW / 1000)?,
            )?);
            store.approve_remote(&host, &request, choice, &signature, NOW / 1000)?;
            let permit = store.initial_permit(&controller, &request, NOW / 1000)?;
            (permit.connection_generation, URL_SAFE_NO_PAD.encode(digest(&permit.encode_to_vec())))
        } else { (1, URL_SAFE_NO_PAD.encode([1; 32])) };
        let current = store.space_details(&controller, &space, NOW)?.space;
        Ok(Self { store, owner, controller, host, signer, space, request,
            binding: NetworkRemotePreparationRequest {
                expected_space_revision: current.revision, expected_policy_epoch: current.policy_epoch,
                connection_generation, permit_sha256,
            },
        })
    }
    fn prepare(&mut self) -> Result<NetworkRemotePreparationBundle> {
        Ok(self.store.prepare_network_remote(&self.controller, &self.signer, &self.space, &self.request, self.binding.clone(), NOW)?)
    }
    fn refresh_revision(&mut self) -> Result {
        let current = self.store.space_details(&self.owner, &self.space, NOW)?.space;
        self.binding.expected_space_revision = current.revision;
        self.binding.expected_policy_epoch = current.policy_epoch;
        Ok(())
    }
}

#[test]
fn ordinary_business_participants_prepare_exact_pair_without_opening_peer_directory() -> Result {
    let mut f = PreparedFixture::new(true)?;
    assert!(!f.controller.is_admin && !f.host.is_admin);
    let details = f.store.space_details(&f.controller, &f.space, NOW)?;
    assert_eq!(details.devices.len(), 1);
    assert_eq!(details.members.len(), 1);
    let before = f.store.space_audit(&f.owner, &f.space, NOW)?.len();
    let pair = f.prepare()?;
    let ids = remote_preparation_grant_ids(&f.space, &f.request, &f.binding)?;
    let business = f.store.current_permit(&f.controller, &f.request, NOW / 1000)?;
    let snapshot = f.store.network_policy_snapshot(&f.space, NOW)?;
    for (index, installation) in [&business.controller_device_id, &business.host_device_id].into_iter().enumerate() {
        let member = verify_network_grant(&pair.memberships[index], &snapshot.verification())?;
        let GrantClaims::Membership(member) = member.claims() else { return Err("not membership".into()); };
        assert_eq!(&member.installation_id, installation);
        assert_eq!(member.scope.grant_id, ids[index]);
        assert_eq!(member.scope.not_before_ms, NOW);
        assert!(member.scope.expires_at_ms <= business.expires_at_unix_ms);
        assert!(member.scope.expires_at_ms <= NOW + 60_000);
    }
    assert!(matches!(f.store.network_membership_grant(&f.controller, &f.space, &ids[1], NOW), Err(StorageError::Forbidden)));
    let duplicate = f.prepare()?;
    let read = f.store.network_remote_preparation(&f.host, &f.space, &f.request, f.binding.clone(), NOW + 1)?;
    for index in 0..2 {
        assert_eq!(pair.memberships[index].claims, read.memberships[index].claims);
        assert_eq!(pair.memberships[index].signature, read.memberships[index].signature);
        assert_eq!(pair.memberships[index].claims, duplicate.memberships[index].claims);
        assert_eq!(pair.memberships[index].signature, duplicate.memberships[index].signature);
    }
    assert_eq!(read.issued_at_ms, NOW);
    assert_eq!(f.store.space_audit(&f.owner, &f.space, NOW + 1)?.len(), before + 2);
    Ok(())
}

#[test]
fn preparation_requires_consent_participation_and_exact_business_and_space_preconditions() -> Result {
    let mut pending = PreparedFixture::new(false)?;
    assert!(pending.prepare().is_err());
    let mut f = PreparedFixture::new(true)?;
    assert!(matches!(f.store.prepare_network_remote(&f.owner, &f.signer, &f.space, &f.request, f.binding.clone(), NOW), Err(StorageError::Forbidden)));
    assert!(f.store.network_remote_preparation(&f.host, &f.space, &f.request, f.binding.clone(), NOW).is_err());
    for case in 0..5 {
        let mut binding = f.binding.clone();
        match case {
            0 => binding.expected_space_revision += 1,
            1 => binding.expected_policy_epoch += 1,
            2 => binding.connection_generation += 1,
            3 => binding.permit_sha256 = URL_SAFE_NO_PAD.encode([2; 32]),
            _ => binding.permit_sha256.push('='),
        }
        assert!(f.store.prepare_network_remote(&f.controller, &f.signer, &f.space, &f.request, binding, NOW).is_err());
    }
    let other = NetworkAuthoritySigner::from_master_seed(&[82; 32])?;
    assert!(f.store.prepare_network_remote(&f.controller, &other, &f.space, &f.request, f.binding.clone(), NOW).is_err());
    let before = f.store.space_audit(&f.owner, &f.space, NOW)?.len();
    f.prepare()?;
    assert_eq!(f.store.space_audit(&f.owner, &f.space, NOW)?.len(), before + 2);
    Ok(())
}

#[test]
fn lost_response_and_revocation_cannot_allocate_a_replacement_pair_by_changing_revision() -> Result {
    let mut f = PreparedFixture::new(true)?;
    let pair = f.prepare()?;
    let original = remote_preparation_grant_ids(&f.space, &f.request, &f.binding)?;
    let read = f.store.network_remote_preparation(&f.controller, &f.space, &f.request, f.binding.clone(), NOW + 2)?;
    assert_eq!(read.memberships[0].claims, pair.memberships[0].claims);
    f.store.revoke_network_grant(&f.owner, NetworkGrantRevocation {
        space_id: f.space.clone(), grant_id: original[1].clone(), expected_revision: f.binding.expected_space_revision,
    }, NOW + 2)?;
    assert!(f.prepare().is_err());
    let current = f.store.space_details(&f.owner, &f.space, NOW + 2)?.space;
    f.binding.expected_space_revision = current.revision;
    f.binding.expected_policy_epoch = current.policy_epoch;
    assert_eq!(remote_preparation_grant_ids(&f.space, &f.request, &f.binding)?, original);
    assert!(f.store.prepare_network_remote(&f.controller, &f.signer, &f.space, &f.request, f.binding.clone(), NOW + 2).is_err());
    assert!(f.store.network_remote_preparation(&f.host, &f.space, &f.request, f.binding.clone(), NOW + 2).is_err());
    Ok(())
}

#[test]
fn membership_epoch_and_device_or_archive_revocation_override_retained_pair() -> Result {
    for case in 0..4 {
        let mut f = PreparedFixture::new(true)?;
        let pair = f.prepare()?;
        let current = f.store.space_details(&f.owner, &f.space, NOW)?;
        match case {
            0 => {
                let target = current.members.iter().find(|m| m.account_id == f.host.account_id).ok_or("missing host")?;
                f.store.update_space_member(&f.owner, &f.space, &f.host.account_id, SpaceMemberUpdate {
                    expected_revision: current.space.revision, expected_member_epoch: target.member_epoch, role: SpaceRole::Guest,
                }, NOW)?;
            }
            1 => {
                let target = current.members.iter().find(|m| m.account_id == f.host.account_id).ok_or("missing host")?;
                f.store.remove_space_member(&f.owner, &f.space, &f.host.account_id, SpaceMemberRemoval {
                    expected_revision: current.space.revision, expected_member_epoch: target.member_epoch,
                }, NOW)?;
            }
            2 => {
                let GrantClaims::Membership(member) = GrantClaims::decode_canonical(&pair.memberships[1].claims)? else { return Err("not membership".into()); };
                f.store.revoke_device_as(&f.host, &random_id(), &member.installation_id, NOW / 1000)?;
            }
            _ => { f.store.archive_space(&f.owner, &f.space, SpaceRevisionRequest { expected_revision: current.space.revision }, NOW)?; }
        }
        f.refresh_revision()?;
        assert!(f.prepare().is_err());
        assert!(f.store.network_remote_preparation(&f.controller, &f.space, &f.request, f.binding.clone(), NOW).is_err());
    }
    Ok(())
}

#[test]
fn partial_pair_collision_and_unknown_request_fields_fail_closed_without_issuing_sibling() -> Result {
    let mut f = PreparedFixture::new(true)?;
    let ids = remote_preparation_grant_ids(&f.space, &f.request, &f.binding)?;
    let business = f.store.current_permit(&f.controller, &f.request, NOW / 1000)?;
    f.store.issue_network_membership(&f.owner, &f.signer, NetworkMembershipRequest {
        space_id: f.space.clone(), installation_id: business.controller_device_id,
        grant_id: ids[0].clone(), expected_policy_epoch: f.binding.expected_policy_epoch,
        expected_membership_epoch: 1, expires_at_ms: business.expires_at_unix_ms.min(NOW + 60_000),
    }, NOW)?;
    let before = f.store.space_audit(&f.owner, &f.space, NOW)?.len();
    assert!(f.prepare().is_err());
    assert!(f.store.network_membership_grant(&f.owner, &f.space, &ids[1], NOW).is_err());
    assert_eq!(f.store.space_audit(&f.owner, &f.space, NOW)?.len(), before);
    let mut body = serde_json::to_value(&f.binding)?;
    body["host_installation_id"] = serde_json::json!(random_id());
    assert!(serde_json::from_value::<NetworkRemotePreparationRequest>(body).is_err());
    Ok(())
}

#[test]
fn original_pair_expiry_is_terminal_for_post_and_readback() -> Result {
    let mut f = PreparedFixture::new(true)?;
    let pair = f.prepare()?;
    let GrantClaims::Membership(member) = GrantClaims::decode_canonical(&pair.memberships[0].claims)? else {
        return Err("not membership".into());
    };
    let end = member.scope.expires_at_ms;
    assert!(f.store.prepare_network_remote(&f.controller, &f.signer, &f.space, &f.request, f.binding.clone(), end).is_err());
    assert!(f.store.network_remote_preparation(&f.host, &f.space, &f.request, f.binding.clone(), end).is_err());
    Ok(())
}
