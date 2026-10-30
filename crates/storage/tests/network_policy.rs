use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{VaultKey, hash_password, random_id};
use nestlink_identity::{
    InstallationIdentity,
    network::{NetworkAuthoritySigner, SignedNetworkGrant, verify_network_grant},
};
use nestlink_protocol::{
    ErrorCode,
    api::{DeviceDescriptor, DeviceRegistration},
    network::{GrantClaims, SpaceRole},
};
use nestlink_storage::{StorageError, Store, accounts::Principal, network_policy::*};
use rusqlite::{Connection, params};
use std::path::PathBuf;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const PASSWORD: &str = "integration-only-password";
const NOW_MS: u64 = 1_000_000;
#[path = "network_policy/authority.rs"]
mod authority_lifecycle;

struct Fixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    deployment: String,
    store: Store,
    admin: Principal,
    member: Principal,
    signer: NetworkAuthoritySigner,
    space: String,
    installation: String,
}

impl Fixture {
    fn new() -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("control.sqlite3");
        let deployment = random_id();
        let mut store = Store::open(&path, &deployment)?;
        let vault = VaultKey::from_bytes([7; 32]);
        let dummy = hash_password("dummy-only-password")?;
        store.bootstrap_admin("admin", PASSWORD)?;
        let admin = store
            .login("admin", PASSWORD, None, NOW_MS / 1000, &vault, &dummy)?
            .principal;
        store.create_member(&admin, "member", PASSWORD)?;
        let member = store
            .login("member", PASSWORD, None, NOW_MS / 1000, &vault, &dummy)?
            .principal;
        let identity = InstallationIdentity::generate();
        let challenge = store.enrollment_challenge(&member, NOW_MS / 1000)?;
        let installation = random_id();
        let mut registration = DeviceRegistration {
            challenge_id: challenge.id,
            device: DeviceDescriptor {
                id: installation.clone(),
                name: "network member".into(),
                platform: "windows".into(),
                public_key: URL_SAFE_NO_PAD.encode(identity.public_key()),
                capabilities: vec!["controller".into()],
                path_mode: "direct_preferred".into(),
            },
            signature: String::new(),
        };
        registration.signature = URL_SAFE_NO_PAD.encode(identity.sign_action(
            &store.registration_transcript(&member, &registration, NOW_MS / 1000)?,
        )?);
        store.register_device(&member, registration, NOW_MS / 1000)?;
        let signer = NetworkAuthoritySigner::from_master_seed(&[42; 32])?;
        let space = random_id();
        let configured = store.configure_network_authority(
            &admin,
            NetworkAuthorityUpdate {
                space_id: space.clone(),
                expected_revision: 0,
                public_key: signer.public_key(),
            },
            NOW_MS,
        )?;
        assert_eq!((configured.revision(), configured.policy_epoch()), (1, 1));
        let configured = store.set_network_membership(
            &admin,
            NetworkMembershipUpdate {
                space_id: space.clone(),
                installation_id: installation.clone(),
                expected_policy_revision: 1,
                expected_membership_epoch: 0,
                role: SpaceRole::Member,
            },
            NOW_MS,
        )?;
        assert_eq!((configured.revision(), configured.policy_epoch()), (2, 2));
        Ok(Self {
            _directory: directory,
            path,
            deployment,
            store,
            admin,
            member,
            signer,
            space,
            installation,
        })
    }
    fn snapshot(&mut self) -> Result<TrustedNetworkPolicySnapshot> {
        Ok(self.store.network_policy_snapshot(&self.space, NOW_MS)?)
    }
    fn request(&mut self, grant: &str) -> Result<NetworkMembershipRequest> {
        let snapshot = self.snapshot()?;
        let epoch = snapshot
            .member(&self.installation)
            .ok_or("member missing")?
            .membership_epoch();
        Ok(NetworkMembershipRequest {
            space_id: self.space.clone(),
            installation_id: self.installation.clone(),
            grant_id: grant.into(),
            expected_policy_epoch: snapshot.policy_epoch(),
            expected_membership_epoch: epoch,
            expires_at_ms: NOW_MS + 60_000,
        })
    }
    fn issue(&mut self, grant: &str) -> Result<SignedNetworkGrant> {
        let request = self.request(grant)?;
        Ok(self
            .store
            .issue_network_membership(&self.admin, &self.signer, request, NOW_MS)?)
    }
}

#[test]
fn signed_membership_and_revocation_survive_restart_without_reissuing_the_id() -> Result {
    let mut f = Fixture::new()?;
    let id = random_id();
    let signed = f.issue(&id)?;
    let verified = f
        .store
        .verify_network_membership(&f.space, &f.installation, &signed, NOW_MS)?;
    assert_eq!(verified.claims().role, SpaceRole::Member);
    let probe = Connection::open(&f.path)?;
    let (claims, signature, digest): (Vec<u8>, Vec<u8>, Vec<u8>) = probe.query_row(
        "SELECT claims,signature,digest FROM network_grants WHERE space_id=?1 AND grant_id=?2",
        params![f.space, id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    assert_eq!(claims, signed.claims);
    assert_eq!(signature, signed.signature);
    assert_eq!(digest, verified.digest());
    drop(probe);
    drop(f.store);
    f.store = Store::open_existing(&f.path, &f.deployment)?;
    f.store
        .verify_network_membership(&f.space, &f.installation, &signed, NOW_MS)?;
    let recovered = f
        .store
        .network_membership_grant(&f.admin, &f.space, &id, NOW_MS)?;
    assert_eq!(recovered.claims, signed.claims);
    assert_eq!(recovered.signature, signed.signature);
    let snapshot = f.snapshot()?;
    let revoked = f.store.revoke_network_grant(
        &f.admin,
        NetworkGrantRevocation {
            space_id: f.space.clone(),
            grant_id: id.clone(),
            expected_revision: snapshot.revision(),
        },
        NOW_MS,
    )?;
    assert_eq!(revoked.revision(), snapshot.revision() + 1);
    let repeated = f.store.revoke_network_grant(
        &f.admin,
        NetworkGrantRevocation {
            space_id: f.space.clone(),
            grant_id: id.clone(),
            expected_revision: revoked.revision(),
        },
        NOW_MS,
    )?;
    assert_eq!(repeated.revision(), revoked.revision());
    drop(f.store);
    f.store = Store::open_existing(&f.path, &f.deployment)?;
    assert!(
        f.store
            .verify_network_membership(&f.space, &f.installation, &signed, NOW_MS)
            .is_err()
    );
    assert!(
        f.store
            .network_membership_grant(&f.admin, &f.space, &id, NOW_MS)
            .is_err()
    );
    let snapshot = f.snapshot()?;
    assert!(snapshot.verification().revoked_grant_ids.contains(&id));
    assert!(
        matches!(verify_network_grant(&signed,&snapshot.verification()),Err(e) if e.code==ErrorCode::PolicyRevoked)
    );
    assert!(f.issue(&id).is_err());
    Ok(())
}

#[test]
fn old_member_epochs_cannot_return_after_revoke_rejoin_or_restart() -> Result {
    let mut f = Fixture::new()?;
    let original = f.issue(&random_id())?;
    let before = f.snapshot()?;
    let revoked = f.store.revoke_network_membership(
        &f.admin,
        NetworkMembershipRevocation {
            space_id: f.space.clone(),
            installation_id: f.installation.clone(),
            expected_policy_revision: before.revision(),
            expected_membership_epoch: 1,
        },
        NOW_MS,
    )?;
    assert_eq!(revoked.policy_epoch(), before.policy_epoch() + 1);
    let member = revoked.member(&f.installation).ok_or("missing member")?;
    assert_eq!(member.membership_epoch(), 2);
    assert!(!member.active());
    assert!(
        f.store
            .verify_network_membership(&f.space, &f.installation, &original, NOW_MS)
            .is_err()
    );
    assert!(
        f.store
            .set_network_membership(
                &f.admin,
                NetworkMembershipUpdate {
                    space_id: f.space.clone(),
                    installation_id: f.installation.clone(),
                    expected_policy_revision: revoked.revision(),
                    expected_membership_epoch: 1,
                    role: SpaceRole::Owner,
                },
                NOW_MS
            )
            .is_err()
    );
    let joined = f.store.set_network_membership(
        &f.admin,
        NetworkMembershipUpdate {
            space_id: f.space.clone(),
            installation_id: f.installation.clone(),
            expected_policy_revision: revoked.revision(),
            expected_membership_epoch: 2,
            role: SpaceRole::Guest,
        },
        NOW_MS,
    )?;
    assert_eq!(
        joined
            .member(&f.installation)
            .ok_or("missing member")?
            .membership_epoch(),
        3
    );
    assert_eq!(joined.policy_epoch(), revoked.policy_epoch() + 1);
    drop(f.store);
    f.store = Store::open_existing(&f.path, &f.deployment)?;
    assert_eq!(
        f.snapshot()?
            .member(&f.installation)
            .ok_or("missing member")?
            .membership_epoch(),
        3
    );
    assert!(
        f.store
            .verify_network_membership(&f.space, &f.installation, &original, NOW_MS)
            .is_err()
    );
    let fresh = f.issue(&random_id())?;
    let verified = f
        .store
        .verify_network_membership(&f.space, &f.installation, &fresh, NOW_MS)?;
    assert_eq!(
        (verified.claims().membership_epoch, verified.claims().role),
        (3, SpaceRole::Guest)
    );
    Ok(())
}

#[test]
fn key_rotation_advances_policy_and_stale_writers_cannot_sign_or_overwrite_it() -> Result {
    let mut f = Fixture::new()?;
    let signed = f.issue(&random_id())?;
    let old = f.snapshot()?;
    let next_signer = NetworkAuthoritySigner::from_master_seed(&[43; 32])?;
    let rotated = f.store.configure_network_authority(
        &f.admin,
        NetworkAuthorityUpdate {
            space_id: f.space.clone(),
            expected_revision: old.revision(),
            public_key: next_signer.public_key(),
        },
        NOW_MS,
    )?;
    assert_eq!(rotated.policy_epoch(), old.policy_epoch() + 1);
    assert!(
        f.store
            .configure_network_authority(
                &f.admin,
                NetworkAuthorityUpdate {
                    space_id: f.space.clone(),
                    expected_revision: old.revision(),
                    public_key: f.signer.public_key(),
                },
                NOW_MS
            )
            .is_err()
    );
    assert!(
        f.store
            .verify_network_membership(&f.space, &f.installation, &signed, NOW_MS)
            .is_err()
    );
    let request = f.request(&random_id())?;
    assert!(
        f.store
            .issue_network_membership(&f.admin, &f.signer, request, NOW_MS)
            .is_err()
    );
    f.signer = next_signer;
    let fresh = f.issue(&random_id())?;
    drop(f.store);
    f.store = Store::open_existing(&f.path, &f.deployment)?;
    assert_eq!(f.snapshot()?.policy_epoch(), rotated.policy_epoch());
    f.store
        .verify_network_membership(&f.space, &f.installation, &fresh, NOW_MS)?;
    Ok(())
}

#[test]
fn valid_signatures_without_committed_issuance_and_wrong_installations_are_rejected() -> Result {
    let mut f = Fixture::new()?;
    let signed = f.issue(&random_id())?;
    assert!(
        f.store
            .verify_network_membership(&f.space, &random_id(), &signed, NOW_MS)
            .is_err()
    );
    let mut claims = GrantClaims::decode_canonical(&signed.claims)?;
    let GrantClaims::Membership(ref mut member) = claims else {
        return Err("wrong test claim kind".into());
    };
    member.scope.grant_id = random_id();
    let unrecorded = f.signer.sign(&claims)?;
    let snapshot = f.snapshot()?;
    verify_network_grant(&unrecorded, &snapshot.verification())?;
    assert!(matches!(
        f.store
            .verify_network_membership(&f.space, &f.installation, &unrecorded, NOW_MS),
        Err(StorageError::Forbidden)
    ));
    let mut request = f.request(&random_id())?;
    request.expected_membership_epoch += 1;
    assert!(matches!(
        f.store
            .issue_network_membership(&f.admin, &f.signer, request, NOW_MS),
        Err(StorageError::Conflict)
    ));
    let mut request = f.request(&random_id())?;
    request.expected_policy_epoch -= 1;
    assert!(matches!(
        f.store
            .issue_network_membership(&f.admin, &f.signer, request, NOW_MS),
        Err(StorageError::Conflict)
    ));
    for expires_at_ms in [NOW_MS, NOW_MS + MAX_MEMBERSHIP_GRANT_MS + 1] {
        let mut request = f.request(&random_id())?;
        request.expires_at_ms = expires_at_ms;
        assert!(
            f.store
                .issue_network_membership(&f.admin, &f.signer, request, NOW_MS)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn signed_grant_and_policy_changes_roll_back_when_their_audit_transaction_fails() -> Result {
    let mut f = Fixture::new()?;
    let connection = Connection::open(&f.path)?;
    let before = f.snapshot()?;
    connection.execute_batch("CREATE TRIGGER network_issue_abort BEFORE INSERT ON audit WHEN NEW.event='network_membership_issued' BEGIN SELECT RAISE(ABORT,'injected audit failure'); END;")?;
    let id = random_id();
    assert!(f.issue(&id).is_err());
    assert_eq!(
        connection.query_row(
            "SELECT count(*) FROM network_grants WHERE grant_id=?1",
            [&id],
            |r| r.get::<_, u64>(0)
        )?,
        0
    );
    connection.execute_batch("DROP TRIGGER network_issue_abort; CREATE TRIGGER network_member_abort BEFORE INSERT ON audit WHEN NEW.event='network_membership_changed' BEGIN SELECT RAISE(ABORT,'injected audit failure'); END;")?;
    assert!(
        f.store
            .set_network_membership(
                &f.admin,
                NetworkMembershipUpdate {
                    space_id: f.space.clone(),
                    installation_id: f.installation.clone(),
                    expected_policy_revision: before.revision(),
                    expected_membership_epoch: 1,
                    role: SpaceRole::Admin,
                },
                NOW_MS
            )
            .is_err()
    );
    let after = f.snapshot()?;
    assert_eq!(
        (after.revision(), after.policy_epoch()),
        (before.revision(), before.policy_epoch())
    );
    let member = after.member(&f.installation).ok_or("member missing")?;
    assert_eq!(
        (member.membership_epoch(), member.role()),
        (1, SpaceRole::Member)
    );
    connection.execute_batch("DROP TRIGGER network_member_abort;")?;
    f.issue(&id)?;
    Ok(())
}

#[test]
fn deployment_admin_session_is_rechecked_for_every_mutation() -> Result {
    let mut f = Fixture::new()?;
    let mut forged = f.member.clone();
    forged.is_admin = true;
    let revision = f.snapshot()?.revision();
    for actor in [&f.member, &forged] {
        assert!(
            f.store
                .configure_network_authority(
                    actor,
                    NetworkAuthorityUpdate {
                        space_id: random_id(),
                        expected_revision: 0,
                        public_key: f.signer.public_key()
                    },
                    NOW_MS
                )
                .is_err()
        );
        assert!(
            f.store
                .set_network_membership(
                    actor,
                    NetworkMembershipUpdate {
                        space_id: f.space.clone(),
                        installation_id: f.installation.clone(),
                        expected_policy_revision: revision,
                        expected_membership_epoch: 1,
                        role: SpaceRole::Owner
                    },
                    NOW_MS
                )
                .is_err()
        );
        assert!(
            f.store
                .revoke_network_membership(
                    actor,
                    NetworkMembershipRevocation {
                        space_id: f.space.clone(),
                        installation_id: f.installation.clone(),
                        expected_policy_revision: revision,
                        expected_membership_epoch: 1
                    },
                    NOW_MS
                )
                .is_err()
        );
        assert!(
            f.store
                .issue_network_membership(
                    actor,
                    &f.signer,
                    NetworkMembershipRequest {
                        space_id: f.space.clone(),
                        installation_id: f.installation.clone(),
                        grant_id: random_id(),
                        expected_policy_epoch: 2,
                        expected_membership_epoch: 1,
                        expires_at_ms: NOW_MS + 60_000
                    },
                    NOW_MS
                )
                .is_err()
        );
        assert!(
            f.store
                .revoke_network_grant(
                    actor,
                    NetworkGrantRevocation {
                        space_id: f.space.clone(),
                        grant_id: random_id(),
                        expected_revision: revision
                    },
                    NOW_MS
                )
                .is_err()
        );
    }
    assert!(matches!(
        f.store.configure_network_authority(
            &f.admin,
            NetworkAuthorityUpdate {
                space_id: random_id(),
                expected_revision: 0,
                public_key: f.signer.public_key(),
            },
            1_300_000
        ),
        Err(StorageError::Unauthorized)
    ));
    Ok(())
}

#[test]
fn external_device_revocation_expiry_and_key_corruption_enter_the_live_snapshot() -> Result {
    for cause in 0..4 {
        let mut f = Fixture::new()?;
        let signed = f.issue(&random_id())?;
        let before = f.snapshot()?;
        let verified = verify_network_grant(&signed, &before.verification())?;
        let connection = Connection::open(&f.path)?;
        match cause {
            0 => {
                f.store.revoke_device_as(
                    &f.member,
                    &random_id(),
                    &f.installation,
                    NOW_MS / 1000,
                )?;
            }
            1 => {
                connection.execute(
                    "UPDATE devices SET expires_at=?1 WHERE id=?2",
                    params![NOW_MS / 1000, f.installation],
                )?;
            }
            2 => {
                connection.execute(
                    "UPDATE accounts SET disabled=1 WHERE id=?1",
                    [&f.member.account_id],
                )?;
            }
            _ => {
                connection.execute(
                    "UPDATE devices SET key_sha256=?1 WHERE id=?2",
                    params![[90u8; 32].as_slice(), f.installation],
                )?;
            }
        }
        let current = f.snapshot()?;
        assert!(
            !current
                .member(&f.installation)
                .ok_or("member missing")?
                .active()
        );
        assert!(
            matches!(verified.check_current(&current.verification()),Err(e) if e.code==ErrorCode::PolicyRevoked)
        );
        assert!(
            f.store
                .verify_network_membership(&f.space, &f.installation, &signed, NOW_MS)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn restart_cannot_roll_the_authorization_clock_back_and_restore_fences_old_spaces() -> Result {
    let mut f = Fixture::new()?;
    let signed = f.issue(&random_id())?;
    let backup = f.store.snapshot()?;
    f.store.network_policy_snapshot(&f.space, NOW_MS + 1000)?;
    drop(f.store);
    f.store = Store::open_existing(&f.path, &f.deployment)?;
    assert!(matches!(
        f.store.network_policy_snapshot(&f.space, NOW_MS),
        Err(StorageError::Conflict)
    ));
    assert!(
        f.store
            .verify_network_membership(&f.space, &f.installation, &signed, NOW_MS)
            .is_err()
    );
    f.store
        .verify_network_membership(&f.space, &f.installation, &signed, NOW_MS + 1000)?;
    let mut restored = Store::from_snapshot(&backup, &f.deployment)?;
    restored.invalidate_after_restore()?;
    assert!(matches!(
        restored.network_policy_snapshot(&f.space, NOW_MS + 1000),
        Err(StorageError::Forbidden)
    ));
    assert!(
        restored
            .verify_network_membership(&f.space, &f.installation, &signed, NOW_MS + 1000)
            .is_err()
    );
    let vault = VaultKey::from_bytes([7; 32]);
    let dummy = hash_password("dummy-only-password")?;
    let admin = restored
        .login(
            "admin",
            PASSWORD,
            None,
            (NOW_MS + 1000) / 1000,
            &vault,
            &dummy,
        )?
        .principal;
    assert!(matches!(
        restored.configure_network_authority(
            &admin,
            NetworkAuthorityUpdate {
                space_id: f.space.clone(),
                expected_revision: 2,
                public_key: f.signer.public_key(),
            },
            NOW_MS + 1000
        ),
        Err(StorageError::Forbidden)
    ));
    let replacement = restored.configure_network_authority(
        &admin,
        NetworkAuthorityUpdate {
            space_id: random_id(),
            expected_revision: 0,
            public_key: f.signer.public_key(),
        },
        NOW_MS + 1000,
    )?;
    assert!(verify_network_grant(&signed, &replacement.verification()).is_err());
    Ok(())
}

#[test]
fn migration_from_schema_twenty_five_creates_no_network_authority() -> Result {
    let f = Fixture::new()?;
    let deployment = f.deployment.clone();
    let path = f.path.clone();
    drop(f.store);
    let connection = Connection::open(&path)?;
    connection.execute_batch("DROP VIEW all_relay_capacity; DROP TABLE space_service_rules; DROP TABLE space_service_bindings; DROP TABLE network_space_audit; DROP TABLE network_space_invitations; DROP TABLE network_space_members; DROP TABLE network_spaces; DROP TABLE network_remote_relays; DROP TABLE network_remote_paths; DROP TABLE network_grant_revocations; DROP TABLE network_grants; DROP TABLE network_memberships; DROP TABLE network_authority_key_history; DROP TABLE network_authorities; PRAGMA user_version=25;")?;
    drop(connection);
    let mut migrated = Store::open_existing(&path, &deployment)?;
    assert!(migrated.network_policy_snapshot(&f.space, NOW_MS).is_err());
    assert_eq!(
        Store::existing_schema(&path, &deployment)?,
        nestlink_storage::SCHEMA_VERSION
    );
    Ok(())
}

#[test]
fn policy_snapshot_fails_closed_when_persisted_member_count_exceeds_its_bound() -> Result {
    let mut f = Fixture::new()?;
    let mut connection = Connection::open(&f.path)?;
    let tx = connection.transaction()?;
    for index in 0..MAX_NETWORK_MEMBERS {
        let installation = random_id();
        let mut key_hash = [0u8; 32];
        key_hash[..8].copy_from_slice(&(index as u64).to_be_bytes());
        tx.execute(
            "INSERT INTO devices(id,account_id,key_sha256) VALUES(?1,?2,?3)",
            params![installation, f.member.account_id, key_hash.as_slice()],
        )?;
        tx.execute("INSERT INTO network_memberships(space_id,installation_id,public_key,membership_epoch,role,revoked) VALUES(?1,?2,?3,1,'member',0)",
            params![f.space,installation,[9u8;32].as_slice()])?;
    }
    tx.commit()?;
    assert!(matches!(
        f.store.network_policy_snapshot(&f.space, NOW_MS),
        Err(StorageError::RateLimited)
    ));
    Ok(())
}

#[test]
fn legacy_deployment_and_path_policy_changes_invalidate_network_grants_atomically() -> Result {
    let mut f = Fixture::new()?;
    let signed = f.issue(&random_id())?;
    let original = f.snapshot()?;
    let (revision, policy) = f.store.policy()?;
    f.store
        .apply_policy_as(&f.admin, NOW_MS / 1000, revision, policy)?;
    let changed = f.snapshot()?;
    assert_eq!(changed.policy_epoch(), original.policy_epoch() + 1);
    assert!(
        matches!(verify_network_grant(&signed,&changed.verification()),Err(e) if e.code==ErrorCode::PolicyRevoked)
    );
    let fresh = f.issue(&random_id())?;
    let (revision, _) = f.store.policy()?;
    f.store
        .set_path_limit(&f.admin, "device", &f.installation, "direct_only", revision)?;
    let tightened = f.snapshot()?;
    assert_eq!(tightened.policy_epoch(), changed.policy_epoch() + 1);
    assert!(
        matches!(verify_network_grant(&fresh,&tightened.verification()),Err(e) if e.code==ErrorCode::PolicyRevoked)
    );
    Ok(())
}
