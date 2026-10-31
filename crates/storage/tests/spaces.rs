//! Real SQLite transactions exercise product delegation and invitation boundaries.
#[path = "spaces/addressing.rs"]
mod addressing;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{VaultKey, hash_password, random_id, token_hash};
use nestlink_identity::{InstallationIdentity, network::NetworkAuthoritySigner};
use nestlink_protocol::{
    api::{DeviceDescriptor, DeviceRegistration},
    network::SpaceRole,
    spaces::*,
};
use nestlink_storage::{
    StorageError, Store, accounts::Principal, network_policy::NetworkMembershipRequest,
};
use rusqlite::{Connection, params};
use std::{
    path::PathBuf,
    sync::{Arc, Barrier},
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const NOW: u64 = 1_000_000;
const PASSWORD: &str = "space-integration-password";

struct Fixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    deployment: String,
    store: Store,
    owner: Principal,
    alice: Principal,
    bob: Principal,
    signer: NetworkAuthoritySigner,
    space: SpaceView,
}

impl Fixture {
    fn new() -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("spaces.sqlite3");
        let deployment = random_id();
        let mut store = Store::open(&path, &deployment)?;
        store.bootstrap_admin("owner", PASSWORD)?;
        let vault = VaultKey::from_bytes([71; 32]);
        let dummy = hash_password("space-dummy-password")?;
        let owner = store
            .login("owner", PASSWORD, None, NOW / 1000, &vault, &dummy)?
            .principal;
        store.create_member(&owner, "alice", PASSWORD)?;
        store.create_member(&owner, "bob", PASSWORD)?;
        let alice = store
            .login("alice", PASSWORD, None, NOW / 1000, &vault, &dummy)?
            .principal;
        let bob = store
            .login("bob", PASSWORD, None, NOW / 1000, &vault, &dummy)?
            .principal;
        let signer = NetworkAuthoritySigner::from_master_seed(&[33; 32])?;
        let space = store.create_space(
            &owner,
            SpaceCreateRequest {
                name: "Test space".into(),
            },
            signer.public_key(),
            NOW,
        )?;
        Ok(Self {
            _directory: directory,
            path,
            deployment,
            store,
            owner,
            alice,
            bob,
            signer,
            space,
        })
    }

    fn view(&self) -> Result<SpaceView> {
        Ok(self
            .store
            .space_details(&self.owner, &self.space.space_id, NOW)?
            .space)
    }

    fn invite(
        &mut self,
        actor: &Principal,
        target: Option<String>,
        role: SpaceRole,
    ) -> Result<SpaceInvitationIssued> {
        let revision = self.view()?.revision;
        Ok(self.store.invite_to_space(
            actor,
            &self.space.space_id,
            SpaceInvitationRequest {
                expected_revision: revision,
                role,
                target_account_id: target,
                expires_at_unix_ms: NOW + 60_000,
            },
            NOW,
        )?)
    }

    fn accept(
        &mut self,
        actor: &Principal,
        invitation: &SpaceInvitationIssued,
    ) -> Result<SpaceView> {
        Ok(self.store.accept_space_invitation(
            actor,
            &self.space.space_id,
            &invitation.invitation.invitation_id,
            SpaceInvitationAcceptance {
                token: invitation.token.clone(),
            },
            NOW,
        )?)
    }

    fn enroll(&mut self, actor: &Principal) -> Result<String> {
        let identity = InstallationIdentity::generate();
        let challenge = self.store.enrollment_challenge(actor, NOW / 1000)?;
        let id = random_id();
        let mut registration = DeviceRegistration {
            challenge_id: challenge.id,
            device: DeviceDescriptor {
                id: id.clone(),
                name: "space device".into(),
                platform: "windows".into(),
                public_key: URL_SAFE_NO_PAD.encode(identity.public_key()),
                capabilities: vec!["controller".into()],
                path_mode: "direct_preferred".into(),
            },
            signature: String::new(),
        };
        registration.signature =
            URL_SAFE_NO_PAD.encode(identity.sign_action(&self.store.registration_transcript(
                actor,
                &registration,
                NOW / 1000,
            )?)?);
        self.store
            .register_device(actor, registration, NOW / 1000)?;
        Ok(id)
    }
}

#[test]
fn invitations_are_scoped_targeted_single_use_and_never_stored_as_plaintext() -> Result {
    let mut f = Fixture::new()?;
    let invitation = f.invite(
        &f.owner.clone(),
        Some(f.alice.account_id.clone()),
        SpaceRole::Member,
    )?;
    assert!(matches!(
        f.store.space_details(&f.alice, &f.space.space_id, NOW),
        Err(StorageError::Forbidden)
    ));
    assert!(f.store.spaces(&f.alice, NOW)?.is_empty());
    assert!(matches!(
        f.store.accept_space_invitation(
            &f.bob,
            &f.space.space_id,
            &invitation.invitation.invitation_id,
            SpaceInvitationAcceptance {
                token: invitation.token.clone()
            },
            NOW
        ),
        Err(StorageError::Forbidden)
    ));
    assert!(
        f.store
            .accept_space_invitation(
                &f.alice,
                &random_id(),
                &invitation.invitation.invitation_id,
                SpaceInvitationAcceptance {
                    token: invitation.token.clone()
                },
                NOW
            )
            .is_err()
    );
    assert!(
        f.store
            .accept_space_invitation(
                &f.alice,
                &f.space.space_id,
                &invitation.invitation.invitation_id,
                SpaceInvitationAcceptance {
                    token: "x".repeat(43)
                },
                NOW
            )
            .is_err()
    );
    let view = f.accept(&f.alice.clone(), &invitation)?;
    assert_eq!(view.role, SpaceRole::Member);
    assert!(f.accept(&f.alice.clone(), &invitation).is_err());
    let private = f.store.space_details(&f.alice, &f.space.space_id, NOW)?;
    assert_eq!(private.members.len(), 1);
    assert!(private.invitations.is_empty());
    assert!(
        f.store
            .space_audit(&f.alice, &f.space.space_id, NOW)
            .is_err()
    );
    let connection = Connection::open(&f.path)?;
    let saved: Vec<u8> = connection.query_row(
        "SELECT token_hash FROM network_space_invitations WHERE invitation_id=?1",
        [&invitation.invitation.invitation_id],
        |r| r.get(0),
    )?;
    assert_eq!(saved, token_hash("space-invitation", &invitation.token));
    let audit: String = connection.query_row(
        "SELECT group_concat(event || resource_id || actor_json) FROM audit",
        [],
        |r| r.get(0),
    )?;
    assert!(!audit.contains(&invitation.token));
    assert_eq!(
        f.store.space_audit(&f.owner, &f.space.space_id, NOW)?.len(),
        3
    );
    Ok(())
}

#[test]
fn expiry_revocation_and_lost_issuer_role_reject_unconsumed_invitations() -> Result {
    let mut f = Fixture::new()?;
    let expired = f.invite(&f.owner.clone(), None, SpaceRole::Guest)?;
    assert!(
        f.store
            .accept_space_invitation(
                &f.alice,
                &f.space.space_id,
                &expired.invitation.invitation_id,
                SpaceInvitationAcceptance {
                    token: expired.token
                },
                NOW + 60_000
            )
            .is_err()
    );
    let revoked = f.invite(&f.owner.clone(), None, SpaceRole::Member)?;
    f.store.revoke_space_invitation(
        &f.owner,
        &f.space.space_id,
        &revoked.invitation.invitation_id,
        SpaceRevisionRequest {
            expected_revision: revoked.space.revision,
        },
        NOW,
    )?;
    assert!(f.accept(&f.alice.clone(), &revoked).is_err());
    let admin = f.invite(
        &f.owner.clone(),
        Some(f.alice.account_id.clone()),
        SpaceRole::Admin,
    )?;
    let accepted = f.accept(&f.alice.clone(), &admin)?;
    let delegated = f.invite(&f.alice.clone(), None, SpaceRole::Guest)?;
    f.store.update_space_member(
        &f.owner,
        &f.space.space_id,
        &f.alice.account_id,
        SpaceMemberUpdate {
            expected_revision: delegated.space.revision,
            expected_member_epoch: accepted.member_epoch,
            role: SpaceRole::Member,
        },
        NOW,
    )?;
    assert!(f.accept(&f.bob.clone(), &delegated).is_err());
    Ok(())
}

#[test]
fn admin_can_delegate_only_member_or_guest_and_owner_transfer_is_atomic() -> Result {
    let mut f = Fixture::new()?;
    let invite = f.invite(&f.owner.clone(), None, SpaceRole::Admin)?;
    let admin = f.accept(&f.alice.clone(), &invite)?;
    assert!(f.invite(&f.alice.clone(), None, SpaceRole::Admin).is_err());
    assert!(f.invite(&f.alice.clone(), None, SpaceRole::Owner).is_err());
    let invite = f.invite(&f.alice.clone(), None, SpaceRole::Guest)?;
    let guest = f.accept(&f.bob.clone(), &invite)?;
    assert!(f.invite(&f.bob.clone(), None, SpaceRole::Guest).is_err());
    assert!(
        f.store
            .update_space_member(
                &f.alice,
                &f.space.space_id,
                &f.owner.account_id,
                SpaceMemberUpdate {
                    expected_revision: guest.revision,
                    expected_member_epoch: 1,
                    role: SpaceRole::Guest
                },
                NOW
            )
            .is_err()
    );
    let changed = f.store.update_space_member(
        &f.alice,
        &f.space.space_id,
        &f.bob.account_id,
        SpaceMemberUpdate {
            expected_revision: guest.revision,
            expected_member_epoch: guest.member_epoch,
            role: SpaceRole::Member,
        },
        NOW,
    )?;
    let transferred = f.store.update_space_member(
        &f.owner,
        &f.space.space_id,
        &f.alice.account_id,
        SpaceMemberUpdate {
            expected_revision: changed.revision,
            expected_member_epoch: admin.member_epoch,
            role: SpaceRole::Owner,
        },
        NOW,
    )?;
    assert_eq!(transferred.role, SpaceRole::Admin);
    assert_eq!(
        f.store
            .space_details(&f.alice, &f.space.space_id, NOW)?
            .space
            .role,
        SpaceRole::Owner
    );
    assert!(
        f.store
            .archive_space(
                &f.owner,
                &f.space.space_id,
                SpaceRevisionRequest {
                    expected_revision: transferred.revision
                },
                NOW
            )
            .is_err()
    );
    let connection = Connection::open(&f.path)?;
    let count: u64 = connection.query_row("SELECT count(*) FROM network_space_members WHERE space_id=?1 AND role='owner' AND revoked=0", [&f.space.space_id], |r| r.get(0))?;
    assert_eq!(count, 1);
    Ok(())
}

#[test]
fn member_removal_revokes_devices_credentials_and_old_cas_without_restoring_on_rejoin() -> Result {
    let mut f = Fixture::new()?;
    let invite = f.invite(&f.owner.clone(), None, SpaceRole::Member)?;
    let joined = f.accept(&f.alice.clone(), &invite)?;
    let device = f.enroll(&f.alice.clone())?;
    let wrong = f.enroll(&f.bob.clone())?;
    assert!(
        f.store
            .join_space_device(
                &f.alice,
                &f.space.space_id,
                SpaceDeviceJoin {
                    expected_revision: joined.revision,
                    expected_membership_epoch: 0,
                    installation_id: wrong
                },
                NOW
            )
            .is_err()
    );
    let view = f.store.join_space_device(
        &f.alice,
        &f.space.space_id,
        SpaceDeviceJoin {
            expected_revision: joined.revision,
            expected_membership_epoch: 0,
            installation_id: device.clone(),
        },
        NOW,
    )?;
    let grant = f.store.issue_network_membership(
        &f.owner,
        &f.signer,
        NetworkMembershipRequest {
            space_id: f.space.space_id.clone(),
            installation_id: device.clone(),
            grant_id: random_id(),
            expected_policy_epoch: view.policy_epoch,
            expected_membership_epoch: 1,
            expires_at_ms: NOW + 30_000,
        },
        NOW,
    )?;
    f.store
        .verify_network_membership(&f.space.space_id, &device, &grant, NOW)?;
    let removed = f.store.remove_space_member(
        &f.owner,
        &f.space.space_id,
        &f.alice.account_id,
        SpaceMemberRemoval {
            expected_revision: view.revision,
            expected_member_epoch: joined.member_epoch,
        },
        NOW,
    )?;
    assert!(removed.policy_epoch > view.policy_epoch);
    assert!(
        f.store
            .verify_network_membership(&f.space.space_id, &device, &grant, NOW)
            .is_err()
    );
    assert!(
        f.store
            .space_details(&f.alice, &f.space.space_id, NOW)
            .is_err()
    );
    assert!(
        f.store
            .join_space_device(
                &f.alice,
                &f.space.space_id,
                SpaceDeviceJoin {
                    expected_revision: view.revision,
                    expected_membership_epoch: 1,
                    installation_id: device.clone()
                },
                NOW
            )
            .is_err()
    );
    let invite = f.invite(&f.owner.clone(), None, SpaceRole::Guest)?;
    let rejoined = f.accept(&f.alice.clone(), &invite)?;
    assert!(rejoined.member_epoch > joined.member_epoch);
    assert!(
        !f.store
            .space_details(&f.alice, &f.space.space_id, NOW)?
            .devices[0]
            .active
    );
    assert!(
        f.store
            .join_space_device(
                &f.alice,
                &f.space.space_id,
                SpaceDeviceJoin {
                    expected_revision: rejoined.revision,
                    expected_membership_epoch: 1,
                    installation_id: device.clone()
                },
                NOW
            )
            .is_err()
    );
    let latest = f.store.space_details(&f.alice, &f.space.space_id, NOW)?;
    f.store.join_space_device(
        &f.alice,
        &f.space.space_id,
        SpaceDeviceJoin {
            expected_revision: rejoined.revision,
            expected_membership_epoch: latest.devices[0].membership_epoch,
            installation_id: device,
        },
        NOW,
    )?;
    Ok(())
}

#[test]
fn archive_is_durable_and_fences_all_network_admission_and_pending_invitations() -> Result {
    let mut f = Fixture::new()?;
    let invite = f.invite(&f.owner.clone(), None, SpaceRole::Guest)?;
    let archived = f.store.archive_space(
        &f.owner,
        &f.space.space_id,
        SpaceRevisionRequest {
            expected_revision: invite.space.revision,
        },
        NOW,
    )?;
    assert!(archived.archived);
    assert!(
        f.store
            .network_policy_snapshot(&f.space.space_id, NOW)
            .is_err()
    );
    assert!(f.accept(&f.alice.clone(), &invite).is_err());
    drop(f.store);
    f.store = Store::open_existing(&f.path, &f.deployment)?;
    assert!(f.view()?.archived);
    assert!(
        f.store
            .invite_to_space(
                &f.owner,
                &f.space.space_id,
                SpaceInvitationRequest {
                    expected_revision: archived.revision,
                    role: SpaceRole::Member,
                    target_account_id: None,
                    expires_at_unix_ms: NOW + 1000
                },
                NOW
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn concurrent_invitation_consumption_commits_exactly_one_membership() -> Result {
    let mut f = Fixture::new()?;
    let invite = f.invite(&f.owner.clone(), None, SpaceRole::Member)?;
    let barrier = Arc::new(Barrier::new(2));
    let mut workers = Vec::new();
    for actor in [f.alice.clone(), f.bob.clone()] {
        let barrier = barrier.clone();
        let path = f.path.clone();
        let deployment = f.deployment.clone();
        let space = f.space.space_id.clone();
        let id = invite.invitation.invitation_id.clone();
        let secret = invite.token.clone();
        let mut store = Store::open_existing(&path, &deployment)?;
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            Ok::<_, String>(
                store
                    .accept_space_invitation(
                        &actor,
                        &space,
                        &id,
                        SpaceInvitationAcceptance { token: secret },
                        NOW,
                    )
                    .is_ok(),
            )
        }));
    }
    let mut successes = 0;
    for worker in workers {
        successes += usize::from(
            worker
                .join()
                .map_err(|_| "invitation worker panicked")?
                .map_err(std::io::Error::other)?,
        );
    }
    assert_eq!(successes, 1);
    let connection = Connection::open(&f.path)?;
    let count: u64 = connection.query_row(
        "SELECT count(*) FROM network_space_members WHERE space_id=?1",
        params![f.space.space_id],
        |r| r.get(0),
    )?;
    assert_eq!(count, 2);
    Ok(())
}

#[test]
fn disabled_members_can_be_removed_and_cannot_delegate_or_read_credentials() -> Result {
    let mut f = Fixture::new()?;
    let invitation = f.invite(&f.owner.clone(), None, SpaceRole::Admin)?;
    let joined = f.accept(&f.alice.clone(), &invitation)?;
    let delegated = f.invite(
        &f.alice.clone(),
        Some(f.bob.account_id.clone()),
        SpaceRole::Guest,
    )?;
    let device = f.enroll(&f.alice.clone())?;
    let view = f.store.join_space_device(
        &f.alice,
        &f.space.space_id,
        SpaceDeviceJoin {
            expected_revision: delegated.space.revision,
            expected_membership_epoch: 0,
            installation_id: device.clone(),
        },
        NOW,
    )?;
    let grant_id = random_id();
    let signed = f.store.issue_network_membership(
        &f.alice,
        &f.signer,
        NetworkMembershipRequest {
            space_id: f.space.space_id.clone(),
            installation_id: device.clone(),
            grant_id: grant_id.clone(),
            expected_policy_epoch: view.policy_epoch,
            expected_membership_epoch: 1,
            expires_at_ms: NOW + 30_000,
        },
        NOW,
    )?;
    f.store.disable_account(&f.owner, &f.alice.account_id)?;
    assert!(
        f.store
            .network_membership_grant(&f.alice, &f.space.space_id, &grant_id, NOW)
            .is_err()
    );
    assert!(
        f.store
            .verify_network_membership(&f.space.space_id, &device, &signed, NOW)
            .is_err()
    );
    assert!(f.accept(&f.bob.clone(), &delegated).is_err());
    let details = f.store.space_details(&f.owner, &f.space.space_id, NOW)?;
    assert!(
        !details
            .members
            .iter()
            .find(|member| member.account_id == f.alice.account_id)
            .ok_or("disabled member missing")?
            .active
    );
    let removed = f.store.remove_space_member(
        &f.owner,
        &f.space.space_id,
        &f.alice.account_id,
        SpaceMemberRemoval {
            expected_revision: view.revision,
            expected_member_epoch: joined.member_epoch,
        },
        NOW,
    )?;
    assert!(removed.policy_epoch > view.policy_epoch);
    assert!(
        f.store
            .remove_space_member(
                &f.owner,
                &f.space.space_id,
                &f.alice.account_id,
                SpaceMemberRemoval {
                    expected_revision: removed.revision,
                    expected_member_epoch: joined.member_epoch + 1
                },
                NOW
            )
            .is_err()
    );
    let connection = Connection::open(&f.path)?;
    let revoked: bool = connection.query_row(
        "SELECT revoked=1 FROM network_space_members WHERE space_id=?1 AND account_id=?2",
        params![f.space.space_id, f.alice.account_id],
        |row| row.get(0),
    )?;
    assert!(revoked);
    Ok(())
}

#[test]
fn disabling_an_active_space_owner_requires_explicit_transfer_or_archive_and_is_audited() -> Result
{
    let mut f = Fixture::new()?;
    let private = f.store.create_space(
        &f.bob,
        SpaceCreateRequest {
            name: "Bob owned".into(),
        },
        f.signer.public_key(),
        NOW,
    )?;
    assert!(matches!(
        f.store.disable_account(&f.owner, &f.bob.account_id),
        Err(StorageError::Conflict)
    ));
    assert_eq!(
        f.store
            .space_details(&f.bob, &private.space_id, NOW)?
            .space
            .role,
        SpaceRole::Owner
    );
    let connection = Connection::open(&f.path)?;
    let blocked: u64 = connection.query_row("SELECT count(*) FROM audit WHERE event='account_disable_blocked_space_owner' AND resource_id=?1", [&f.bob.account_id], |row| row.get(0))?;
    assert_eq!(blocked, 1);
    let invitation = f.store.invite_to_space(
        &f.bob,
        &private.space_id,
        SpaceInvitationRequest {
            expected_revision: private.revision,
            role: SpaceRole::Member,
            target_account_id: Some(f.alice.account_id.clone()),
            expires_at_unix_ms: NOW + 60_000,
        },
        NOW,
    )?;
    let joined = f.store.accept_space_invitation(
        &f.alice,
        &private.space_id,
        &invitation.invitation.invitation_id,
        SpaceInvitationAcceptance {
            token: invitation.token,
        },
        NOW,
    )?;
    let transferred = f.store.update_space_member(
        &f.bob,
        &private.space_id,
        &f.alice.account_id,
        SpaceMemberUpdate {
            expected_revision: joined.revision,
            expected_member_epoch: joined.member_epoch,
            role: SpaceRole::Owner,
        },
        NOW,
    )?;
    f.store.disable_account(&f.owner, &f.bob.account_id)?;
    assert!(matches!(
        f.store.disable_account(&f.owner, &f.alice.account_id),
        Err(StorageError::Conflict)
    ));
    let current = f
        .store
        .space_details(&f.alice, &private.space_id, NOW)?
        .space;
    assert_eq!(current.role, SpaceRole::Owner);
    assert_eq!(current.revision, transferred.revision);
    f.store.archive_space(
        &f.alice,
        &private.space_id,
        SpaceRevisionRequest {
            expected_revision: current.revision,
        },
        NOW,
    )?;
    f.store.disable_account(&f.owner, &f.alice.account_id)?;
    Ok(())
}

#[test]
fn exact_credential_readback_uses_current_product_delegation_and_preserves_legacy_admin_rules()
-> Result {
    use nestlink_storage::network_policy::{NetworkAuthorityUpdate, NetworkMembershipUpdate};
    let mut f = Fixture::new()?;
    let invitation = f.invite(&f.owner.clone(), None, SpaceRole::Member)?;
    f.accept(&f.alice.clone(), &invitation)?;
    let invitation = f.invite(&f.owner.clone(), None, SpaceRole::Guest)?;
    let bob = f.accept(&f.bob.clone(), &invitation)?;
    let device = f.enroll(&f.alice.clone())?;
    let view = f.store.join_space_device(
        &f.alice,
        &f.space.space_id,
        SpaceDeviceJoin {
            expected_revision: bob.revision,
            expected_membership_epoch: 0,
            installation_id: device.clone(),
        },
        NOW,
    )?;
    let grant_id = random_id();
    let space_id = f.space.space_id.clone();
    let request = || NetworkMembershipRequest {
        space_id: space_id.clone(),
        installation_id: device.clone(),
        grant_id: grant_id.clone(),
        expected_policy_epoch: view.policy_epoch,
        expected_membership_epoch: 1,
        expires_at_ms: NOW + 30_000,
    };
    let signed = f
        .store
        .issue_network_membership(&f.alice, &f.signer, request(), NOW)?;
    assert!(matches!(
        f.store
            .issue_network_membership(&f.alice, &f.signer, request(), NOW),
        Err(StorageError::Conflict)
    ));
    let recovered =
        f.store
            .network_membership_grant(&f.alice, &f.space.space_id, &grant_id, NOW)?;
    assert_eq!(recovered.claims, signed.claims);
    assert_eq!(recovered.signature, signed.signature);
    f.store
        .network_membership_grant(&f.owner, &f.space.space_id, &grant_id, NOW)?;
    assert!(matches!(
        f.store
            .network_membership_grant(&f.bob, &f.space.space_id, &grant_id, NOW),
        Err(StorageError::Forbidden)
    ));
    let promoted = f.store.update_space_member(
        &f.owner,
        &f.space.space_id,
        &f.bob.account_id,
        SpaceMemberUpdate {
            expected_revision: view.revision,
            expected_member_epoch: bob.member_epoch,
            role: SpaceRole::Admin,
        },
        NOW,
    )?;
    assert!(
        f.store
            .network_membership_grant(&f.alice, &f.space.space_id, &grant_id, NOW)
            .is_err()
    );
    let admin_grant = random_id();
    f.store.issue_network_membership(
        &f.bob,
        &f.signer,
        NetworkMembershipRequest {
            space_id: f.space.space_id.clone(),
            installation_id: device.clone(),
            grant_id: admin_grant.clone(),
            expected_policy_epoch: promoted.policy_epoch,
            expected_membership_epoch: 1,
            expires_at_ms: NOW + 30_000,
        },
        NOW,
    )?;
    f.store
        .network_membership_grant(&f.bob, &f.space.space_id, &admin_grant, NOW)?;
    let demoted = f.store.update_space_member(
        &f.owner,
        &f.space.space_id,
        &f.bob.account_id,
        SpaceMemberUpdate {
            expected_revision: promoted.revision,
            expected_member_epoch: bob.member_epoch + 1,
            role: SpaceRole::Guest,
        },
        NOW,
    )?;
    let current_grant = random_id();
    f.store.issue_network_membership(
        &f.alice,
        &f.signer,
        NetworkMembershipRequest {
            space_id: f.space.space_id.clone(),
            installation_id: device.clone(),
            grant_id: current_grant.clone(),
            expected_policy_epoch: demoted.policy_epoch,
            expected_membership_epoch: 1,
            expires_at_ms: NOW + 30_000,
        },
        NOW,
    )?;
    assert!(matches!(
        f.store
            .network_membership_grant(&f.bob, &f.space.space_id, &current_grant, NOW),
        Err(StorageError::Forbidden)
    ));
    f.store.archive_space(
        &f.owner,
        &f.space.space_id,
        SpaceRevisionRequest {
            expected_revision: demoted.revision,
        },
        NOW,
    )?;
    assert!(
        f.store
            .network_membership_grant(&f.alice, &f.space.space_id, &current_grant, NOW)
            .is_err()
    );
    let legacy = random_id();
    f.store.configure_network_authority(
        &f.owner,
        NetworkAuthorityUpdate {
            space_id: legacy.clone(),
            expected_revision: 0,
            public_key: f.signer.public_key(),
        },
        NOW,
    )?;
    let policy = f.store.set_network_membership(
        &f.owner,
        NetworkMembershipUpdate {
            space_id: legacy.clone(),
            installation_id: device.clone(),
            expected_policy_revision: 1,
            expected_membership_epoch: 0,
            role: SpaceRole::Member,
        },
        NOW,
    )?;
    let legacy_grant = random_id();
    f.store.issue_network_membership(
        &f.owner,
        &f.signer,
        NetworkMembershipRequest {
            space_id: legacy.clone(),
            installation_id: device,
            grant_id: legacy_grant.clone(),
            expected_policy_epoch: policy.policy_epoch(),
            expected_membership_epoch: 1,
            expires_at_ms: NOW + 30_000,
        },
        NOW,
    )?;
    assert!(matches!(
        f.store
            .network_membership_grant(&f.alice, &legacy, &legacy_grant, NOW),
        Err(StorageError::Forbidden)
    ));
    f.store
        .network_membership_grant(&f.owner, &legacy, &legacy_grant, NOW)?;
    Ok(())
}
