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
}
impl Setup {
    fn new(approve: bool) -> Result<Self> {
        let (mut store, _, _, controller, host) = fixture()?;
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
                path_mode: "direct_only".into(),
            },
            NOW / 1000,
        )?;
        if approve {
            let choice = ApprovalChoice {
                approved: true,
                permissions: vec![Permission::View as i32],
                paths: vec![Path::Direct as i32],
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
    for fault in 0..6 {
        let mut issuance = f.issuance();
        match fault {
            0 => issuance.space_id = random_id(),
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
