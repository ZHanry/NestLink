//! Actual SDK -> HTTP middleware -> SQLite directory and revocation boundaries.
use nestlink_auth::{Secret, VaultKey, random_id};
use nestlink_identity::PermitSigner;
use nestlink_protocol::{network::SpaceRole, spaces::addressing::*, spaces::*};
use nestlink_sdk::{DeploymentTrust, DeviceIdentity, Sdk, SdkError};
use nestlink_server::{AppState, router};
use nestlink_storage::Store;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const PASSWORD: &str = "addressing-http-integration-password";

struct Server(tokio::task::JoinHandle<std::io::Result<()>>);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn login(origin: &str, trust: DeploymentTrust, user: &str) -> Result<Sdk> {
    let mut sdk = Sdk::connect(origin, trust, true).await?;
    sdk.login(user.into(), Secret::from_text(PASSWORD.into()), None)
        .await?;
    Ok(sdk)
}

fn status<T>(result: std::result::Result<T, SdkError>, expected: u16) {
    assert!(matches!(result,Err(SdkError::Api(status,_)) if status.as_u16()==expected));
}

#[tokio::test]
async fn directory_issue_reserve_rename_revoke_are_real_authorized_http_calls() -> Result {
    let deployment = random_id();
    let signer = PermitSigner::generate();
    let trust = DeploymentTrust {
        deployment_id: deployment.clone(),
        permit_issuer: signer.public_key(),
    };
    let mut store = Store::in_memory(&deployment)?;
    store.bootstrap_admin("owner", PASSWORD)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let app = router(AppState::new(
        store,
        VaultKey::from_bytes([91; 32]),
        signer,
        origin.clone(),
        false,
    )?);
    let _server = Server(tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
    }));
    let owner = login(
        &origin,
        DeploymentTrust {
            deployment_id: trust.deployment_id.clone(),
            permit_issuer: trust.permit_issuer,
        },
        "owner",
    )
    .await?;
    owner
        .create_account("member".into(), Secret::from_text(PASSWORD.into()))
        .await?;
    let member = login(&origin, trust, "member").await?;
    let member_id = member
        .principal()
        .ok_or("missing member principal")?
        .account_id
        .clone();
    let owner_device = DeviceIdentity::generate();
    owner
        .enroll(
            &owner_device,
            "Owner".into(),
            "linux".into(),
            vec!["controller".into()],
            "direct_preferred".into(),
        )
        .await?;
    let member_device = DeviceIdentity::generate();
    member
        .enroll(
            &member_device,
            "Member".into(),
            "windows".into(),
            vec!["controller".into()],
            "direct_preferred".into(),
        )
        .await?;
    let space = owner
        .create_space(SpaceCreateRequest {
            name: "IPAM HTTP".into(),
        })
        .await?;
    let id = &space.space_id;
    status(member.space_address_directory(id).await, 403);
    let invitation = owner
        .invite_to_space(
            id,
            SpaceInvitationRequest {
                expected_revision: space.revision,
                role: SpaceRole::Member,
                target_account_id: Some(member_id),
                expires_at_unix_ms: space.observed_at_unix_ms + 60_000,
            },
        )
        .await?;
    let joined = member
        .accept_space_invitation(
            id,
            &invitation.invitation.invitation_id,
            SpaceInvitationAcceptance {
                token: invitation.token,
            },
        )
        .await?;
    let joined = member
        .join_space_device(
            id,
            SpaceDeviceJoin {
                expected_revision: joined.revision,
                expected_membership_epoch: 0,
                installation_id: member_device.device_id.clone(),
            },
        )
        .await?;
    let joined = owner
        .join_space_device(
            id,
            SpaceDeviceJoin {
                expected_revision: joined.revision,
                expected_membership_epoch: 0,
                installation_id: owner_device.device_id.clone(),
            },
        )
        .await?;
    let empty = owner.space_address_directory(id).await?;
    assert_eq!(empty.revision, 0);
    assert!(empty.addresses.is_empty());
    status(
        member
            .issue_space_address(
                id,
                SpaceAddressIssue {
                    expected_revision: 0,
                    expected_address_epoch: 0,
                    expected_membership_epoch: 1,
                    installation_id: member_device.device_id.clone(),
                    name: "member".into(),
                },
            )
            .await,
        403,
    );
    let first = owner
        .issue_space_address(
            id,
            SpaceAddressIssue {
                expected_revision: 0,
                expected_address_epoch: 0,
                expected_membership_epoch: 1,
                installation_id: owner_device.device_id.clone(),
                name: "NAS".into(),
            },
        )
        .await?;
    assert_eq!(first.space.revision, joined.revision);
    assert_eq!(first.space.policy_epoch, joined.policy_epoch);
    let initial = first.addresses[0].clone();
    assert!(initial.active);
    assert_eq!(initial.name, "nas");
    assert_eq!(
        initial.public_key,
        base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            owner_device.identity.public_key()
        )
    );
    assert!(
        member
            .space_address_directory(id)
            .await?
            .addresses
            .is_empty()
    );
    let second = owner
        .issue_space_address(
            id,
            SpaceAddressIssue {
                expected_revision: first.revision,
                expected_address_epoch: 0,
                expected_membership_epoch: 1,
                installation_id: member_device.device_id.clone(),
                name: "member".into(),
            },
        )
        .await?;
    assert_eq!(second.addresses.len(), 2);
    assert_eq!(
        member.space_address_directory(id).await?.addresses[0].installation_id,
        member_device.device_id
    );
    status(
        owner
            .rename_space_address(
                id,
                &owner_device.device_id,
                SpaceAddressRename {
                    expected_revision: first.revision,
                    expected_address_epoch: 1,
                    name: "stale".into(),
                },
            )
            .await,
        409,
    );
    status(
        owner
            .rename_space_address(
                id,
                &owner_device.device_id,
                SpaceAddressRename {
                    expected_revision: second.revision,
                    expected_address_epoch: 1,
                    name: "MEMBER".into(),
                },
            )
            .await,
        409,
    );
    let renamed = owner
        .rename_space_address(
            id,
            &owner_device.device_id,
            SpaceAddressRename {
                expected_revision: second.revision,
                expected_address_epoch: 1,
                name: "Files".into(),
            },
        )
        .await?;
    let row = renamed
        .addresses
        .iter()
        .find(|a| a.installation_id == owner_device.device_id)
        .ok_or("missing owner address")?;
    assert_eq!(row.name, "files");
    assert_eq!(row.ipv4, initial.ipv4);
    let reserved = owner
        .reserve_space_address(
            id,
            &owner_device.device_id,
            SpaceAddressReservation {
                expected_revision: renamed.revision,
                expected_address_epoch: 2,
                ipv4: "100.100.12.8".into(),
                ipv6: "fd4e:6573:744c::c008".into(),
            },
        )
        .await?;
    assert!(
        reserved
            .addresses
            .iter()
            .any(|a| a.installation_id == owner_device.device_id
                && a.reserved
                && a.ipv4 == "100.100.12.8")
    );
    status(
        member
            .revoke_space_address(
                id,
                &owner_device.device_id,
                SpaceAddressRevocation {
                    expected_revision: reserved.revision,
                    expected_address_epoch: 3,
                },
            )
            .await,
        403,
    );
    let revoked = owner
        .revoke_space_address(
            id,
            &owner_device.device_id,
            SpaceAddressRevocation {
                expected_revision: reserved.revision,
                expected_address_epoch: 3,
            },
        )
        .await?;
    assert!(
        revoked
            .addresses
            .iter()
            .any(|a| a.installation_id == owner_device.device_id && a.revoked && !a.active)
    );
    status(
        owner
            .issue_space_address(
                id,
                SpaceAddressIssue {
                    expected_revision: revoked.revision,
                    expected_address_epoch: 1,
                    expected_membership_epoch: 1,
                    installation_id: owner_device.device_id.clone(),
                    name: "files".into(),
                },
            )
            .await,
        409,
    );
    let reissued = owner
        .issue_space_address(
            id,
            SpaceAddressIssue {
                expected_revision: revoked.revision,
                expected_address_epoch: 4,
                expected_membership_epoch: 1,
                installation_id: owner_device.device_id.clone(),
                name: "files".into(),
            },
        )
        .await?;
    let current = reissued
        .addresses
        .iter()
        .find(|a| a.installation_id == owner_device.device_id)
        .ok_or("missing reissued address")?;
    assert_eq!(current.address_epoch, 5);
    assert_ne!(current.ipv4, initial.ipv4);
    owner
        .remove_space_device(
            id,
            &member_device.device_id,
            SpaceDeviceRemoval {
                expected_revision: joined.revision,
                expected_membership_epoch: 1,
            },
        )
        .await?;
    assert!(
        member
            .space_address_directory(id)
            .await?
            .addresses
            .is_empty()
    );
    assert!(
        owner
            .space_address_directory(id)
            .await?
            .addresses
            .iter()
            .any(|a| a.installation_id == member_device.device_id && !a.active)
    );
    Ok(())
}
