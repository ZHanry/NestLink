use super::*;
use nestlink_identity::network::{NetworkAuthoritySigner, verify_network_grant};
use nestlink_protocol::{
    Path,
    api::NetworkRemotePathRequest,
    network::{GrantClaims, Purpose, SpaceRole},
};
use nestlink_storage::network_policy::*;

const NOW: u64 = 1_002_000;
struct Setup {
    store: Store,
    controller: Principal,
    host: Principal,
    signer: NetworkAuthoritySigner,
    space: String,
    request: String,
    controller_member: String,
    host_member: String,
    controller_identity: InstallationIdentity,
    host_identity: InstallationIdentity,
}
impl Setup {
    fn new(approve: bool) -> Result<Self> {
        Self::with_path(approve, true)
    }
    fn with_path(approve: bool, direct: bool) -> Result<Self> {
        let (mut store, _, _, controller, host) = fixture()?;
        if !direct {
            store.apply_policy(1, nestlink_policy::NetworkPolicy {
                server_forwarding: nestlink_policy::ServerForwarding::Allow,
                peer_path_mode: nestlink_policy::PeerPathMode::DirectPreferred,
                ..nestlink_policy::NetworkPolicy::default()
            })?;
        }
        let c = InstallationIdentity::generate();
        let h = InstallationIdentity::generate();
        let cid = enroll(&mut store, &controller, &c, "controller")?;
        let hid = enroll(&mut store, &host, &h, "host")?;
        let signer = NetworkAuthoritySigner::from_master_seed(&[63; 32])?;
        let space = random_id();
        store.configure_network_authority(
            &controller,
            NetworkAuthorityUpdate {
                space_id: space.clone(),
                expected_revision: 0,
                public_key: signer.public_key(),
            },
            NOW,
        )?;
        for (revision, id) in [(1, &cid), (2, &hid)] {
            store.set_network_membership(
                &controller,
                NetworkMembershipUpdate {
                    space_id: space.clone(),
                    installation_id: id.clone(),
                    expected_policy_revision: revision,
                    expected_membership_epoch: 0,
                    role: SpaceRole::Member,
                },
                NOW,
            )?;
        }
        let controller_member = random_id();
        let host_member = random_id();
        for (id, installation) in [(&controller_member, &cid), (&host_member, &hid)] {
            store.issue_network_membership(
                &controller,
                &signer,
                NetworkMembershipRequest {
                    space_id: space.clone(),
                    installation_id: installation.clone(),
                    grant_id: id.clone(),
                    expected_policy_epoch: 3,
                    expected_membership_epoch: 1,
                    expires_at_ms: NOW + 60_000,
                },
                NOW,
            )?;
        }
        let view = store.create_remote(
            &controller,
            RemoteRequest {
                id: random_id(),
                controller_device_id: cid,
                host_device_id: hid,
                permissions: vec![Permission::View as i32],
                path_mode: if direct { "direct_only" } else { "relay_only" }.into(),
            },
            NOW / 1000,
        )?;
        if approve {
            let choice = ApprovalChoice {
                approved: true,
                permissions: vec![Permission::View as i32],
                paths: vec![if direct { Path::Direct } else { Path::Relay } as i32],
            };
            let proof = store.approval_transcript(&host, &view.id, &choice, NOW / 1000)?;
            let signature = URL_SAFE_NO_PAD.encode(h.sign_action(&proof)?);
            store.approve_remote(&host, &view.id, choice, &signature, NOW / 1000)?;
            store.initial_permit(&controller, &view.id, NOW / 1000)?;
        }
        Ok(Self {
            store,
            controller,
            host,
            signer,
            space,
            request: view.id,
            controller_member,
            host_member,
            controller_identity: c,
            host_identity: h,
        })
    }
    fn issuance(&self) -> NetworkRemotePathIssuance {
        NetworkRemotePathIssuance {
            space_id: self.space.clone(),
            request_id: self.request.clone(),
            request: NetworkRemotePathRequest {
                connectivity_grant_id: random_id(),
                path_grant_id: random_id(),
                controller_membership_grant_id: self.controller_member.clone(),
                host_membership_grant_id: self.host_member.clone(),
                expected_policy_epoch: 3,
                expires_at_unix_ms: NOW + 2_000,
            },
        }
    }
}

#[test]
fn live_business_consent_produces_an_exact_device_bound_direct_chain_and_readback() -> Result {
    let mut f = Setup::new(true)?;
    let issuance = f.issuance();
    let id = issuance.request.path_grant_id.clone();
    let bundle = f
        .store
        .issue_network_remote_path(&f.controller, &f.signer, issuance, NOW)?;
    assert_eq!(bundle.verified().purpose(), Purpose::RemoteControl);
    assert!(bundle.verified().claims().policy.allow_direct);
    assert_eq!(bundle.verified().claims().policy.max_hops, 0);
    let business = f
        .store
        .current_permit(&f.controller, &f.request, NOW / 1000)?;
    let snapshot = f.store.network_policy_snapshot(&f.space, NOW)?;
    let connection = verify_network_grant(&bundle.connectivity, &snapshot.verification())?;
    let GrantClaims::Connectivity(claims) = connection.claims() else {
        return Err("not connectivity".into());
    };
    use prost::Message;
    assert_eq!(
        claims.business_grant_digest,
        digest(&business.encode_to_vec())
    );
    let read = f.store.network_remote_path(&f.host, &f.space, &id, NOW)?;
    assert_eq!(read.path.claims, bundle.path.claims);
    assert_eq!(read.path.signature, bundle.path.signature);
    assert_eq!(read.connectivity.claims, bundle.connectivity.claims);
    assert_eq!(
        read.verified().transport_group_id(),
        bundle.verified().transport_group_id()
    );
    f.store
        .revoke_network_remote_path(&f.host, &f.space, &id, NOW)?;
    f.store
        .revoke_network_remote_path(&f.host, &f.space, &id, NOW)?;
    assert!(
        f.store
            .network_remote_path(&f.controller, &f.space, &id, NOW)
            .is_err()
    );
    let revoked = f.store.network_policy_snapshot(&f.space, NOW)?;
    assert!(
        bundle
            .verified()
            .check_current(&revoked.verification())
            .is_err()
    );
    Ok(())
}

#[test]
fn membership_and_admin_role_cannot_create_unapproved_remote_authority() -> Result {
    let mut f = Setup::new(false)?;
    let issuance = f.issuance();
    assert!(
        f.store
            .issue_network_remote_path(&f.controller, &f.signer, issuance, NOW)
            .is_err()
    );
    Ok(())
}

#[test]
fn path_admission_rejects_cross_space_copied_membership_stale_epoch_expiry_and_reused_ids() -> Result
{
    let mut f = Setup::new(true)?;
    let foreign_space = random_id();
    f.store.configure_network_authority(&f.controller, NetworkAuthorityUpdate {
        space_id: foreign_space.clone(), expected_revision: 0, public_key: f.signer.public_key(),
    }, NOW)?;
    let business = f.store.current_permit(&f.controller, &f.request, NOW / 1000)?;
    for (revision, installation) in [(1, &business.controller_device_id), (2, &business.host_device_id)] {
        f.store.set_network_membership(&f.controller, NetworkMembershipUpdate {
            space_id: foreign_space.clone(), installation_id: installation.clone(),
            expected_policy_revision: revision, expected_membership_epoch: 0, role: SpaceRole::Member,
        }, NOW)?;
    }
    for fault in 0..6 {
        let mut issuance = f.issuance();
        match fault {
            0 => issuance.space_id = foreign_space.clone(),
            1 => issuance.request.host_membership_grant_id = f.controller_member.clone(),
            2 => issuance.request.expected_policy_epoch = 2,
            3 => issuance.request.expires_at_unix_ms = NOW + 61_000,
            4 => issuance.request.path_grant_id = f.controller_member.clone(),
            _ => issuance.request.path_grant_id = issuance.request.connectivity_grant_id.clone(),
        }
        assert!(
            f.store
                .issue_network_remote_path(&f.controller, &f.signer, issuance, NOW)
                .is_err(),
            "fault {fault}"
        );
    }
    let issuance = f.issuance();
    let retry = NetworkRemotePathIssuance {
        space_id: issuance.space_id.clone(),
        request_id: issuance.request_id.clone(),
        request: issuance.request.clone(),
    };
    let id = issuance.request.path_grant_id.clone();
    f.store
        .issue_network_remote_path(&f.controller, &f.signer, issuance, NOW)?;
    assert!(
        f.store
            .issue_network_remote_path(&f.controller, &f.signer, retry, NOW)
            .is_err()
    );
    assert!(
        f.store
            .network_remote_path(&f.controller, &f.space, &id, NOW + 2_000)
            .is_err()
    );
    Ok(())
}

#[test]
fn live_business_revocation_and_management_logout_stop_path_readback() -> Result {
    for cause in 0..2 {
        let mut f = Setup::new(true)?;
        let issuance = f.issuance();
        let id = issuance.request.path_grant_id.clone();
        f.store
            .issue_network_remote_path(&f.controller, &f.signer, issuance, NOW)?;
        if cause == 0 {
            f.store.revoke_remote(&f.host, &f.request)?;
        } else {
            f.store.logout(&f.controller)?;
        }
        assert!(
            f.store
                .network_remote_path(&f.controller, &f.space, &id, NOW)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn revoking_either_member_grant_stops_new_and_existing_paths() -> Result {
    for controller in [true, false] {
        let mut f = Setup::new(true)?;
        let issuance = f.issuance();
        let id = issuance.request.path_grant_id.clone();
        let bundle = f.store.issue_network_remote_path(&f.controller, &f.signer, issuance, NOW)?;
        f.store.revoke_network_grant(&f.controller, NetworkGrantRevocation {
            space_id: f.space.clone(),
            grant_id: if controller { f.controller_member.clone() } else { f.host_member.clone() },
            expected_revision: 3,
        }, NOW)?;
        assert!(f.store.network_remote_path(&f.host, &f.space, &id, NOW).is_err());
        let snapshot = f.store.network_policy_snapshot(&f.space, NOW)?;
        assert!(bundle.verified().check_current(&snapshot.verification()).is_err());
        let issuance = f.issuance();
        assert!(f.store.issue_network_remote_path(&f.controller, &f.signer, issuance, NOW).is_err());
    }
    Ok(())
}

#[test]
fn renewal_and_reconnection_require_a_new_chain_for_the_exact_business_generation() -> Result {
    use nestlink_protocol::api::{ReconnectionChoice, ReconnectionSubmission};
    use prost::Message;
    for reconnect in [false, true] {
        let mut f = Setup::new(true)?;
        let issuance = f.issuance();
        let id = issuance.request.path_grant_id.clone();
        f.store.issue_network_remote_path(&f.controller, &f.signer, issuance, NOW)?;
        let previous = f.store.current_permit(&f.controller, &f.request, NOW / 1000)?;
        let next_now = NOW / 1000 + 1;
        if reconnect {
            let choice = ReconnectionChoice {
                previous_permit_sha256: URL_SAFE_NO_PAD.encode(digest(&previous.encode_to_vec())),
                connection_generation: previous.connection_generation + 1,
                lease_sequence: previous.lease_sequence + 1,
                nonce: URL_SAFE_NO_PAD.encode([55; 32]),
            };
            let transcript = nestlink_identity::reconnection::transcript;
            f.store.reconnect_permit(&f.controller, &f.request, ReconnectionSubmission {
                controller_signature: URL_SAFE_NO_PAD.encode(f.controller_identity.sign_action(&transcript(&previous, &previous.controller_device_id, &choice)?)?),
                host_signature: URL_SAFE_NO_PAD.encode(f.host_identity.sign_action(&transcript(&previous, &previous.host_device_id, &choice)?)?),
                choice,
            }, next_now)?;
        } else {
            let sequence = previous.lease_sequence + 1;
            let c = f.store.renewal_transcript(&f.controller, &f.request, sequence, false, next_now)?;
            let h = f.store.renewal_transcript(&f.controller, &f.request, sequence, true, next_now)?;
            f.store.renew_permit(&f.controller, &f.request, RenewalSubmission {
                lease_sequence: sequence,
                controller_signature: URL_SAFE_NO_PAD.encode(f.controller_identity.sign_action(&c)?),
                host_signature: URL_SAFE_NO_PAD.encode(f.host_identity.sign_action(&h)?),
            }, next_now)?;
        }
        assert!(matches!(f.store.network_remote_path(&f.host, &f.space, &id, next_now * 1000), Err(StorageError::Forbidden)));
        let issuance = f.issuance();
        f.store.issue_network_remote_path(&f.controller, &f.signer, issuance, next_now * 1000)?;
    }
    Ok(())
}

#[test]
fn relay_only_consent_and_parent_lifetimes_cannot_be_widened_to_direct_paths() -> Result {
    let mut relay = Setup::with_path(true, false)?;
    let issuance = relay.issuance();
    assert!(matches!(relay.store.issue_network_remote_path(&relay.controller, &relay.signer, issuance, NOW), Err(StorageError::Forbidden)));
    let mut f = Setup::new(true)?;
    let business = f.store.current_permit(&f.controller, &f.request, NOW / 1000)?;
    let mut issuance = f.issuance();
    issuance.request.expires_at_unix_ms = business.expires_at_unix_ms + 1;
    assert!(f.store.issue_network_remote_path(&f.controller, &f.signer, issuance, NOW).is_err());
    let short_host = random_id();
    f.store.issue_network_membership(&f.controller, &f.signer, NetworkMembershipRequest {
        space_id: f.space.clone(), installation_id: business.host_device_id,
        grant_id: short_host.clone(), expected_policy_epoch: 3, expected_membership_epoch: 1,
        expires_at_ms: NOW + 1_000,
    }, NOW)?;
    let mut issuance = f.issuance();
    issuance.request.host_membership_grant_id = short_host;
    assert!(f.store.issue_network_remote_path(&f.controller, &f.signer, issuance, NOW).is_err());
    Ok(())
}

fn edit_snapshot(f: &mut Setup, edit: impl FnOnce(&rusqlite::Connection) -> rusqlite::Result<()>) -> Result {
    let deployment = f.store.deployment_id()?;
    let snapshot = f.store.snapshot()?;
    let mut connection = rusqlite::Connection::open_in_memory()?;
    connection.deserialize_read_exact(rusqlite::MAIN_DB, &snapshot[..], snapshot.len(), false)?;
    edit(&connection)?;
    let image = connection.serialize(rusqlite::MAIN_DB)?;
    f.store = Store::from_snapshot(&image, &deployment)?;
    Ok(())
}

#[test]
fn signed_path_readback_cannot_widen_direct_only_consent_to_a_relay_policy() -> Result {
    let mut f = Setup::new(true)?;
    let issuance = f.issuance();
    let id = issuance.request.path_grant_id.clone();
    let bundle = f.store.issue_network_remote_path(&f.controller, &f.signer, issuance, NOW)?;
    let GrantClaims::Path(mut claims) = GrantClaims::decode_canonical(&bundle.path.claims)? else {
        return Err("not path".into());
    };
    claims.policy.relays = vec![nestlink_protocol::network::PeerId([47; 32])];
    claims.policy.max_hops = 1;
    let substituted = f.signer.sign(&GrantClaims::Path(claims))?;
    edit_snapshot(&mut f, |connection| {
        connection.execute("UPDATE network_remote_paths SET path_claims=?1,path_signature=?2",
            rusqlite::params![substituted.claims,substituted.signature])?;
        Ok(())
    })?;
    assert!(matches!(f.store.network_remote_path(&f.controller, &f.space, &id, NOW), Err(StorageError::Forbidden)));
    Ok(())
}

#[test]
fn stale_generations_member_bindings_and_durable_metadata_fail_as_admission_errors() -> Result {
    for fault in 0..9 {
        let mut f = Setup::new(true)?;
        let issuance = f.issuance();
        let id = issuance.request.path_grant_id.clone();
        f.store.issue_network_remote_path(&f.controller, &f.signer, issuance, NOW)?;
        edit_snapshot(&mut f, |connection| {
            let sql = match fault {
                0 => "UPDATE remote_requests SET connection_generation=connection_generation+1",
                1 => "UPDATE sessions SET connection_generation=connection_generation+1",
                2 => "UPDATE network_remote_paths SET connectivity_grant_id='50000000-0000-4000-8000-000000000001'",
                3 => "UPDATE network_remote_paths SET policy_epoch=policy_epoch+1",
                4 => "UPDATE network_remote_paths SET expires_at_ms=expires_at_ms+1",
                5 => "UPDATE network_memberships SET membership_epoch=membership_epoch+1 WHERE installation_id=(SELECT controller_device_id FROM remote_requests LIMIT 1)",
                6 => "UPDATE network_memberships SET membership_epoch=membership_epoch+1 WHERE installation_id=(SELECT host_device_id FROM remote_requests LIMIT 1)",
                7 => "UPDATE device_details SET public_key=zeroblob(32) WHERE device_id=(SELECT controller_device_id FROM remote_requests LIMIT 1)",
                _ => "UPDATE device_details SET public_key=zeroblob(32) WHERE device_id=(SELECT host_device_id FROM remote_requests LIMIT 1)",
            };
            connection.execute(sql, [])?;
            Ok(())
        })?;
        let read = f.store.network_remote_path(&f.controller, &f.space, &id, NOW);
        if fault <= 4 {
            assert!(matches!(read, Err(StorageError::Forbidden)), "fault {fault}");
        } else {
            assert!(read.is_err(), "fault {fault}");
        }
    }
    Ok(())
}
