//! Real typed SDK -> HTTP security middleware -> durable authorization entrypoints.
use nestlink_auth::{Secret, VaultKey, random_id};
use nestlink_identity::PermitSigner;
use nestlink_protocol::{
    api::NetworkIssueRequest,
    network::{GrantClaims, SpaceRole},
    spaces::*,
};
use nestlink_sdk::{
    DeploymentTrust, DeviceIdentity, Sdk, SdkError, network_management::decode_network_grant,
};
use nestlink_server::{AppState, router};
use nestlink_storage::Store;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const PASSWORD: &str = "space-sdk-integration-password";

struct Server(tokio::task::JoinHandle<std::io::Result<()>>);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn forbidden<T>(result: std::result::Result<T, SdkError>) {
    assert!(matches!(result, Err(SdkError::Api(status, _)) if status.as_u16() == 403));
}

#[tokio::test]
async fn space_roles_invites_devices_signed_credentials_and_archive_use_real_server() -> Result {
    let deployment = random_id();
    let signer = PermitSigner::generate();
    let issuer = signer.public_key();
    let mut store = Store::in_memory(&deployment)?;
    store.bootstrap_admin("owner", PASSWORD)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let app = router(AppState::new(
        store,
        VaultKey::from_bytes([63; 32]),
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
    let mut owner = Sdk::connect(
        &origin,
        DeploymentTrust {
            deployment_id: deployment.clone(),
            permit_issuer: issuer,
        },
        true,
    )
    .await?;
    owner
        .login("owner".into(), Secret::from_text(PASSWORD.into()), None)
        .await?;
    owner
        .create_account("alice".into(), Secret::from_text(PASSWORD.into()))
        .await?;
    owner
        .create_account("bob".into(), Secret::from_text(PASSWORD.into()))
        .await?;
    let mut alice = Sdk::connect(
        &origin,
        DeploymentTrust {
            deployment_id: deployment.clone(),
            permit_issuer: issuer,
        },
        true,
    )
    .await?;
    alice
        .login("alice".into(), Secret::from_text(PASSWORD.into()), None)
        .await?;
    let mut bob = Sdk::connect(
        &origin,
        DeploymentTrust {
            deployment_id: deployment,
            permit_issuer: issuer,
        },
        true,
    )
    .await?;
    bob.login("bob".into(), Secret::from_text(PASSWORD.into()), None)
        .await?;
    let alice_account = alice
        .principal()
        .ok_or("alice principal missing")?
        .account_id
        .clone();
    let bob_account = bob
        .principal()
        .ok_or("bob principal missing")?
        .account_id
        .clone();
    let device = DeviceIdentity::generate();
    alice
        .enroll(
            &device,
            "Alice device".into(),
            "windows".into(),
            vec!["controller".into()],
            "direct_preferred".into(),
        )
        .await?;
    // Space creation itself is available to ordinary accounts, not just a
    // deployment administrator. It creates no device/session/service permit.
    let separate = bob
        .create_space(SpaceCreateRequest {
            name: "Bob private".into(),
        })
        .await?;
    let created = owner
        .create_space(SpaceCreateRequest {
            name: "Shared product space".into(),
        })
        .await?;
    let id = &created.space_id;
    forbidden(alice.space_details(id).await);
    assert!(alice.spaces().await?.is_empty());
    forbidden(owner.space_details(&separate.space_id).await);
    let invitation = owner
        .invite_to_space(
            id,
            SpaceInvitationRequest {
                expected_revision: created.revision,
                role: SpaceRole::Admin,
                target_account_id: Some(alice_account.clone()),
                expires_at_unix_ms: created.observed_at_unix_ms + 60_000,
            },
        )
        .await?;
    forbidden(
        bob.accept_space_invitation(
            id,
            &invitation.invitation.invitation_id,
            SpaceInvitationAcceptance {
                token: invitation.token.clone(),
            },
        )
        .await,
    );
    let joined = alice
        .accept_space_invitation(
            id,
            &invitation.invitation.invitation_id,
            SpaceInvitationAcceptance {
                token: invitation.token.clone(),
            },
        )
        .await?;
    assert_eq!(joined.role, SpaceRole::Admin);
    forbidden(
        alice
            .accept_space_invitation(
                id,
                &invitation.invitation.invitation_id,
                SpaceInvitationAcceptance {
                    token: invitation.token,
                },
            )
            .await,
    );
    forbidden(
        alice
            .invite_to_space(
                id,
                SpaceInvitationRequest {
                    expected_revision: joined.revision,
                    role: SpaceRole::Admin,
                    target_account_id: None,
                    expires_at_unix_ms: joined.observed_at_unix_ms + 60_000,
                },
            )
            .await,
    );
    let guest_invitation = alice
        .invite_to_space(
            id,
            SpaceInvitationRequest {
                expected_revision: joined.revision,
                role: SpaceRole::Guest,
                target_account_id: Some(bob_account.clone()),
                expires_at_unix_ms: joined.observed_at_unix_ms + 60_000,
            },
        )
        .await?;
    let guest = bob
        .accept_space_invitation(
            id,
            &guest_invitation.invitation.invitation_id,
            SpaceInvitationAcceptance {
                token: guest_invitation.token,
            },
        )
        .await?;
    assert_eq!(guest.role, SpaceRole::Guest);
    assert_eq!(bob.space_details(id).await?.members.len(), 1);
    forbidden(
        bob.invite_to_space(
            id,
            SpaceInvitationRequest {
                expected_revision: guest.revision,
                role: SpaceRole::Guest,
                target_account_id: None,
                expires_at_unix_ms: guest.observed_at_unix_ms + 60_000,
            },
        )
        .await,
    );
    let device_join = alice
        .join_space_device(
            id,
            SpaceDeviceJoin {
                expected_revision: guest.revision,
                expected_membership_epoch: 0,
                installation_id: device.device_id.clone(),
            },
        )
        .await?;
    assert!(alice.space_details(id).await?.devices[0].active);
    let credential = alice
        .issue_network_membership(
            id,
            &device.device_id,
            NetworkIssueRequest {
                grant_id: random_id(),
                expected_policy_epoch: device_join.policy_epoch,
                expected_membership_epoch: 1,
                expires_at_unix_ms: device_join.observed_at_unix_ms + 30_000,
            },
        )
        .await?;
    let signed = decode_network_grant(&credential)?;
    assert!(matches!(
        GrantClaims::decode_canonical(&signed.claims)?,
        GrantClaims::Membership(_)
    ));
    // A committed request ID cannot be reissued after a lost response. The
    // ordinary account instead recovers exactly the stored signed bytes.
    let retry = alice
        .issue_network_membership(
            id,
            &device.device_id,
            NetworkIssueRequest {
                grant_id: credential.grant_id.clone(),
                expected_policy_epoch: device_join.policy_epoch,
                expected_membership_epoch: 1,
                expires_at_unix_ms: device_join.observed_at_unix_ms + 30_000,
            },
        )
        .await;
    assert!(matches!(retry, Err(SdkError::Api(status, _)) if status.as_u16() == 409));
    let recovered = alice
        .network_membership_grant(id, &credential.grant_id)
        .await?;
    assert_eq!(recovered.claims, credential.claims);
    assert_eq!(recovered.signature, credential.signature);
    let owner_read = owner
        .network_membership_grant(id, &credential.grant_id)
        .await?;
    assert_eq!(owner_read.signature, credential.signature);
    forbidden(bob.network_membership_grant(id, &credential.grant_id).await);
    forbidden(
        alice
            .network_membership_grant(&separate.space_id, &credential.grant_id)
            .await,
    );
    forbidden(
        bob.issue_network_membership(
            id,
            &device.device_id,
            NetworkIssueRequest {
                grant_id: random_id(),
                expected_policy_epoch: device_join.policy_epoch,
                expected_membership_epoch: 1,
                expires_at_unix_ms: device_join.observed_at_unix_ms + 30_000,
            },
        )
        .await,
    );
    let stale = owner
        .update_space_member(
            id,
            &bob_account,
            SpaceMemberUpdate {
                expected_revision: guest.revision,
                expected_member_epoch: guest.member_epoch,
                role: SpaceRole::Member,
            },
        )
        .await;
    assert!(matches!(stale, Err(SdkError::Api(status, _)) if status.as_u16() == 409));
    let removed = owner
        .remove_space_member(
            id,
            &alice_account,
            SpaceMemberRemoval {
                expected_revision: device_join.revision,
                expected_member_epoch: joined.member_epoch,
            },
        )
        .await?;
    forbidden(alice.space_details(id).await);
    forbidden(
        alice
            .network_membership_grant(id, &credential.grant_id)
            .await,
    );
    forbidden(
        owner
            .network_membership_grant(id, &credential.grant_id)
            .await,
    );
    forbidden(
        alice
            .issue_network_membership(
                id,
                &device.device_id,
                NetworkIssueRequest {
                    grant_id: random_id(),
                    expected_policy_epoch: removed.policy_epoch,
                    expected_membership_epoch: 2,
                    expires_at_unix_ms: removed.observed_at_unix_ms + 30_000,
                },
            )
            .await,
    );
    let audit = owner.space_audit(id).await?;
    assert!(
        audit
            .iter()
            .any(|entry| entry.action == "network_space_member_removed")
    );
    forbidden(bob.space_audit(id).await);
    let archived = owner
        .archive_space(
            id,
            SpaceRevisionRequest {
                expected_revision: removed.revision,
            },
        )
        .await?;
    assert!(archived.archived);
    assert!(owner.space_details(id).await?.space.archived);
    forbidden(
        bob.join_space_device(
            id,
            SpaceDeviceJoin {
                expected_revision: archived.revision,
                expected_membership_epoch: 0,
                installation_id: device.device_id,
            },
        )
        .await,
    );
    // Refuse to orphan Bob's current private space. The refusal is durable
    // audit metadata; Bob remains authenticated and explicitly archives it.
    let blocked = owner.disable_account(&bob_account).await;
    assert!(matches!(blocked, Err(SdkError::Api(status, _)) if status.as_u16() == 409));
    assert!(
        owner
            .audit_page(0, 100)
            .await?
            .entries
            .iter()
            .any(|entry| entry.event == "account_disable_blocked_space_owner"
                && entry.resource_id == bob_account)
    );
    assert_eq!(
        bob.space_details(&separate.space_id).await?.space.role,
        SpaceRole::Owner
    );
    bob.archive_space(
        &separate.space_id,
        SpaceRevisionRequest {
            expected_revision: separate.revision,
        },
    )
    .await?;
    let cleanup = owner
        .create_space(SpaceCreateRequest {
            name: "Disabled member cleanup".into(),
        })
        .await?;
    let invitation = owner
        .invite_to_space(
            &cleanup.space_id,
            SpaceInvitationRequest {
                expected_revision: cleanup.revision,
                role: SpaceRole::Member,
                target_account_id: Some(bob_account.clone()),
                expires_at_unix_ms: cleanup.observed_at_unix_ms + 60_000,
            },
        )
        .await?;
    let joined = bob
        .accept_space_invitation(
            &cleanup.space_id,
            &invitation.invitation.invitation_id,
            SpaceInvitationAcceptance {
                token: invitation.token,
            },
        )
        .await?;
    owner.disable_account(&bob_account).await?;
    assert!(
        matches!(bob.space_details(&cleanup.space_id).await, Err(SdkError::Api(status, _)) if status.as_u16() == 401)
    );
    let details = owner.space_details(&cleanup.space_id).await?;
    assert!(
        !details
            .members
            .iter()
            .find(|member| member.account_id == bob_account)
            .ok_or("disabled member missing")?
            .active
    );
    owner
        .remove_space_member(
            &cleanup.space_id,
            &bob_account,
            SpaceMemberRemoval {
                expected_revision: joined.revision,
                expected_member_epoch: joined.member_epoch,
            },
        )
        .await?;
    assert!(
        owner
            .space_audit(&cleanup.space_id)
            .await?
            .iter()
            .any(|entry| entry.action == "network_space_member_removed"
                && entry.target_id == bob_account)
    );
    Ok(())
}
