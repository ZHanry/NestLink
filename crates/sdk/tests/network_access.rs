//! SDK -> real HTTP authentication/middleware -> durable SQLite -> independent
//! network verification. No membership or manager role approves a host port.
use nestlink_auth::{Secret, VaultKey, random_id};
use nestlink_identity::{
    PermitSigner,
    network::{VerifiedMembership, VerifiedNetworkPath, verify_network_grant},
};
use nestlink_protocol::{
    api::NetworkIssueRequest,
    network::{
        Direction, GrantClaims, IpPrefix, IpProtocol, NetworkRule, PeerId, Purpose, SpaceRole,
    },
    network_access::{NetworkAccessRequest, NetworkAccessStart, NetworkAccessView},
    spaces::{addressing::*, *},
};
use nestlink_sdk::{
    DeploymentTrust, DeviceIdentity, Sdk, SdkError, network_management::decode_network_grant,
};
use nestlink_server::{AppState, router};
use nestlink_storage::{StorageError, Store};
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
mod subnet;
const PASSWORD: &str = "packet-access-http-integration-password";

fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
struct Server(tokio::task::JoinHandle<std::io::Result<()>>);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}
fn status<T>(result: std::result::Result<T, SdkError>, expected: u16) {
    assert!(matches!(result,Err(SdkError::Api(status,_)) if status.as_u16()==expected));
}
async fn login(origin: &str, deployment: &str, issuer: [u8; 32], name: &str) -> Result<Sdk> {
    let mut sdk = Sdk::connect(
        origin,
        DeploymentTrust {
            deployment_id: deployment.into(),
            permit_issuer: issuer,
        },
        true,
    )
    .await?;
    sdk.login(name.into(), Secret::from_text(PASSWORD.into()), None)
        .await?;
    Ok(sdk)
}

async fn endpoint(
    manager: &Sdk,
    sdk: &Sdk,
    space: &str,
    name: &str,
) -> Result<(DeviceIdentity, SpaceAddressView)> {
    let device = DeviceIdentity::generate();
    endpoint_identity(manager,sdk,space,name,device).await
}

async fn endpoint_identity(manager:&Sdk,sdk:&Sdk,space:&str,name:&str,device:DeviceIdentity) -> Result<(DeviceIdentity,SpaceAddressView)> {
    sdk.enroll(
        &device,
        name.into(),
        "windows".into(),
        vec!["controller".into()],
        "direct_preferred".into(),
    )
    .await?;
    let revision = manager.space_details(space).await?.space.revision;
    sdk.join_space_device(
        space,
        SpaceDeviceJoin {
            expected_revision: revision,
            expected_membership_epoch: 0,
            installation_id: device.device_id.clone(),
        },
    )
    .await?;
    let directory = manager.space_address_directory(space).await?;
    let directory = manager
        .issue_space_address(
            space,
            SpaceAddressIssue {
                expected_revision: directory.revision,
                expected_address_epoch: 0,
                expected_membership_epoch: 1,
                installation_id: device.device_id.clone(),
                name: name.into(),
            },
        )
        .await?;
    let address = directory
        .addresses
        .into_iter()
        .find(|row| row.installation_id == device.device_id)
        .ok_or("missing endpoint address")?;
    Ok((device, address))
}

struct Fixture {
    _server: Server,
    _directory: tempfile::TempDir,
    database: PathBuf,
    deployment: String,
    manager: Sdk,
    source: Sdk,
    target: Sdk,
    stranger: Sdk,
    source_device: DeviceIdentity,
    target_device: DeviceIdentity,
    space: String,
    request: NetworkAccessRequest,
    authority: [u8;32],
}
impl Fixture {
    async fn new() -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("network-access.sqlite3");
        let deployment = random_id();
        let signer = PermitSigner::generate();
        let issuer = signer.public_key();
        let authority = signer.network_authority_signer()?.public_key();
        let mut store = Store::open(&database, &deployment)?;
        store.bootstrap_admin("manager", PASSWORD)?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("http://{}", listener.local_addr()?);
        let app = router(AppState::new(
            store,
            VaultKey::from_bytes([63; 32]),
            signer,
            origin.clone(),
            false,
        )?);
        let server = Server(tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
        }));
        let manager = login(&origin, &deployment, issuer, "manager").await?;
        for name in ["source", "target", "stranger"] {
            manager
                .create_account(name.into(), Secret::from_text(PASSWORD.into()))
                .await?;
        }
        let source = login(&origin, &deployment, issuer, "source").await?;
        let target = login(&origin, &deployment, issuer, "target").await?;
        let stranger = login(&origin, &deployment, issuer, "stranger").await?;
        let space = manager
            .create_space(SpaceCreateRequest {
                name: "explicit packet access".into(),
            })
            .await?
            .space_id;
        for sdk in [&source, &target, &stranger] {
            let current = manager.space_details(&space).await?.space;
            let invitation = manager
                .invite_to_space(
                    &space,
                    SpaceInvitationRequest {
                        expected_revision: current.revision,
                        role: SpaceRole::Member,
                        target_account_id: Some(
                            sdk.principal()
                                .ok_or("missing principal")?
                                .account_id
                                .clone(),
                        ),
                        expires_at_unix_ms: now()? + 60_000,
                    },
                )
                .await?;
            sdk.accept_space_invitation(
                &space,
                &invitation.invitation.invitation_id,
                SpaceInvitationAcceptance {
                    token: invitation.token,
                },
            )
            .await?;
        }
        // Fixed fixture seeds permit a separately proven node identity to use
        // the same test key without exporting an enrolled installation secret.
        let (source_device, source_address) = endpoint_identity(&manager, &source, &space, "source", DeviceIdentity {device_id:random_id(),identity:nestlink_identity::InstallationIdentity::from_seed([61;32])}).await?;
        let (target_device, target_address) = endpoint_identity(&manager, &target, &space, "target", DeviceIdentity {device_id:random_id(),identity:nestlink_identity::InstallationIdentity::from_seed([62;32])}).await?;
        // A third active directory row must never leak through an endpoint's
        // grant readback, even though a space manager owns this third device.
        endpoint(&manager, &manager, &space, "manager").await?;
        let directory_view = manager.space_address_directory(&space).await?;
        assert_eq!(directory_view.addresses.len(), 3);
        let policy = manager.space_details(&space).await?.space;
        let source_membership = random_id();
        let target_membership = random_id();
        let membership_end = now()? + 45_000;
        for (sdk, device, id) in [
            (&source, &source_device, &source_membership),
            (&target, &target_device, &target_membership),
        ] {
            sdk.issue_network_membership(
                &space,
                &device.device_id,
                NetworkIssueRequest {
                    grant_id: id.clone(),
                    expected_policy_epoch: policy.policy_epoch,
                    expected_membership_epoch: 1,
                    expires_at_unix_ms: membership_end,
                },
            )
            .await?;
        }
        let request = NetworkAccessRequest {
            access_grant_id: random_id(),
            connectivity_grant_id: random_id(),
            path_grant_id: random_id(),
            source_installation_id: source_device.device_id.clone(),
            destination_installation_id: target_device.device_id.clone(),
            source_membership_grant_id: source_membership,
            destination_membership_grant_id: target_membership,
            expected_revision: policy.revision,
            expected_policy_epoch: policy.policy_epoch,
            expected_directory_revision: directory_view.revision,
            expected_source_address_epoch: source_address.address_epoch,
            expected_destination_address_epoch: target_address.address_epoch,
            source_prefixes: vec![
                IpPrefix {
                    network: source_address.ipv4.parse()?,
                    prefix_len: 32,
                },
                IpPrefix {
                    network: source_address.ipv6.parse()?,
                    prefix_len: 128,
                },
            ],
            destination_prefixes: vec![
                IpPrefix {
                    network: target_address.ipv4.parse()?,
                    prefix_len: 32,
                },
                IpPrefix {
                    network: target_address.ipv6.parse()?,
                    prefix_len: 128,
                },
            ],
            rules: vec![
                NetworkRule {
                    protocol: IpProtocol::Tcp,
                    direction: Direction::Inbound,
                    ports: Some([22, 22]),
                },
                NetworkRule {
                    protocol: IpProtocol::Udp,
                    direction: Direction::Inbound,
                    ports: Some([53, 53]),
                },
            ],
            byte_limit: 1024 * 1024,
            expires_at_unix_ms: now()? + 55_000,
        };
        Ok(Self {
            _server: server,
            _directory: directory,
            database,
            deployment,
            manager,
            source,
            target,
            stranger,
            source_device,
            target_device,
            space,
            request,
            authority,
        })
    }
    async fn fresh_request(&self) -> Result<NetworkAccessRequest> {
        let mut request = self.request.clone();
        request.access_grant_id = random_id();
        request.connectivity_grant_id = random_id();
        request.path_grant_id = random_id();
        let current = self.manager.space_details(&self.space).await?.space;
        request.expected_revision = current.revision;
        request.expected_policy_epoch = current.policy_epoch;
        request.expected_directory_revision = self
            .manager
            .space_address_directory(&self.space)
            .await?
            .revision;
        request.expires_at_unix_ms = now()? + 50_000;
        Ok(request)
    }
    fn store(&self) -> Result<Store> {
        Ok(Store::open_existing(&self.database, &self.deployment)?)
    }
    async fn finish(mut self) -> Result {
        self._server.0.abort();
        let _=(&mut self._server.0).await;
        self._directory.close()?;
        Ok(())
    }
}

fn exact_grants(left: &NetworkAccessView, right: &NetworkAccessView) -> Result {
    for (left, right) in [
        (&left.source_membership, &right.source_membership),
        (&left.destination_membership, &right.destination_membership),
        (&left.access, &right.access),
        (&left.connectivity, &right.connectivity),
        (&left.path, &right.path),
    ] {
        assert_eq!(serde_json::to_value(left)?, serde_json::to_value(right)?);
    }
    Ok(())
}

#[tokio::test]
async fn raw_ip_requires_destination_approval_and_returns_one_durable_scoped_graph() -> Result {
    let f = Fixture::new().await?;
    status(
        f.source
            .issue_network_access(&f.space, f.request.clone())
            .await,
        403,
    );
    status(
        f.manager
            .issue_network_access(&f.space, f.request.clone())
            .await,
        403,
    );
    status(
        f.stranger
            .issue_network_access(&f.space, f.request.clone())
            .await,
        403,
    );
    let issued = f
        .target
        .issue_network_access(&f.space, f.request.clone())
        .await?;
    assert_eq!(issued.address_directory.addresses.len(), 2);
    assert_eq!(
        issued.address_directory.addresses[0].installation_id,
        f.source_device.device_id
    );
    assert_eq!(
        issued.address_directory.addresses[1].installation_id,
        f.target_device.device_id
    );
    assert_eq!(
        f.source
            .space_address_directory(&f.space)
            .await?
            .addresses
            .len(),
        1
    );
    assert_eq!(
        f.target
            .space_address_directory(&f.space)
            .await?
            .addresses
            .len(),
        1
    );
    let read = f
        .source
        .network_access(&f.space, &f.request.access_grant_id)
        .await?;
    exact_grants(&issued, &read)?;
    status(
        f.manager
            .network_access(&f.space, &f.request.access_grant_id)
            .await,
        403,
    );
    status(
        f.stranger
            .network_access(&f.space, &f.request.access_grant_id)
            .await,
        403,
    );
    status(
        f.target
            .issue_network_access(&f.space, f.request.clone())
            .await,
        409,
    );

    let mut reopened = f.store()?;
    let snapshot = reopened.network_policy_snapshot(&f.space, now()?)?;
    let access = verify_network_grant(
        &decode_network_grant(&issued.access)?,
        &snapshot.verification(),
    )?;
    let GrantClaims::NetworkAccess(access_claims) = access.claims() else {
        return Err("wrong raw IP business grant".into());
    };
    assert_eq!(
        access_claims.source,
        PeerId::from_public_key(&f.source_device.identity.public_key())
    );
    assert_eq!(
        access_claims.destination,
        PeerId::from_public_key(&f.target_device.identity.public_key())
    );
    assert_eq!(access_claims.rules, f.request.rules);
    assert_eq!(access_claims.byte_limit, f.request.byte_limit);
    assert!(access_claims.scope.expires_at_ms < f.request.expires_at_unix_ms);
    assert!(access_claims.scope.expires_at_ms - access_claims.scope.not_before_ms <= 60_000);
    let mut members = Vec::new();
    for (view, device) in [
        (&issued.source_membership, &f.source_device),
        (&issued.destination_membership, &f.target_device),
    ] {
        members.push(VerifiedMembership::from_grant(
            verify_network_grant(&decode_network_grant(view)?, &snapshot.verification())?,
            &snapshot.verification(),
            &device.device_id,
            &device.identity.public_key(),
            1,
        )?);
    }
    let connection = verify_network_grant(
        &decode_network_grant(&issued.connectivity)?,
        &snapshot.verification(),
    )?;
    let GrantClaims::Connectivity(connection_claims) = connection.claims() else {
        return Err("wrong connectivity grant".into());
    };
    assert_eq!(connection_claims.business_grant_digest, access.digest());
    assert_eq!(connection_claims.purpose, Purpose::NetworkPacket);
    let verified = VerifiedNetworkPath::from_grants(
        &snapshot.verification(),
        [members[0].clone(), members[1].clone()],
        connection,
        verify_network_grant(
            &decode_network_grant(&issued.path)?,
            &snapshot.verification(),
        )?,
        access.digest(),
    )?;
    assert_eq!(verified.purpose(), Purpose::NetworkPacket);
    assert!(verified.claims().policy.allow_direct);
    assert!(verified.claims().policy.relays.is_empty());
    let durable = reopened.network_access(
        f.source.principal().ok_or("missing principal")?,
        &f.space,
        &f.request.access_grant_id,
        now()?,
    )?;
    assert_eq!(
        durable.access.claims,
        decode_network_grant(&issued.access)?.claims
    );
    assert_eq!(
        durable.access.signature,
        decode_network_grant(&issued.access)?.signature
    );
    Ok(())
}

#[tokio::test]
async fn http_rejects_forged_sources_wide_cidrs_cross_purpose_ids_and_unbounded_grants() -> Result {
    let f = Fixture::new().await?;
    let mut request = f.request.clone();
    request.source_prefixes[0] = IpPrefix {
        network: "10.20.30.40".parse()?,
        prefix_len: 32,
    };
    status(f.target.issue_network_access(&f.space, request).await, 403);
    let mut request = f.request.clone();
    request.source_prefixes = vec![IpPrefix {
        network: "100.64.0.0".parse()?,
        prefix_len: 10,
    }];
    status(f.target.issue_network_access(&f.space, request).await, 403);
    let mut request = f.request.clone();
    request.expires_at_unix_ms = now()? + 120_000;
    status(f.target.issue_network_access(&f.space, request).await, 400);
    let mut request = f.request.clone();
    request.expected_policy_epoch += 1;
    status(f.target.issue_network_access(&f.space, request).await, 409);
    let mut request = f.request.clone();
    request.expected_directory_revision += 1;
    status(f.target.issue_network_access(&f.space, request).await, 409);
    let mut request = f.request.clone();
    request.access_grant_id = request.source_membership_grant_id.clone();
    status(f.target.issue_network_access(&f.space, request).await, 409);
    let mut request = f.request.clone();
    request.destination_membership_grant_id = request.source_membership_grant_id.clone();
    status(f.target.issue_network_access(&f.space, request).await, 403);
    let other_space = f
        .manager
        .create_space(SpaceCreateRequest {
            name: "unrelated packet scope".into(),
        })
        .await?;
    status(
        f.target
            .issue_network_access(&other_space.space_id, f.request.clone())
            .await,
        403,
    );
    // No rejected call consumed the valid graph ID or changed its revision.
    let issued = f
        .target
        .issue_network_access(&f.space, f.request.clone())
        .await?;
    assert_eq!(issued.access.grant_id, f.request.access_grant_id);
    Ok(())
}

#[tokio::test]
async fn either_endpoint_and_space_manager_can_deny_but_revocation_never_reissues_graph_ids()
-> Result {
    let f = Fixture::new().await?;
    let issued = f
        .target
        .issue_network_access(&f.space, f.request.clone())
        .await?;
    let revision = f.manager.space_details(&f.space).await?.space.revision;
    status(
        f.stranger
            .revoke_network_access(&f.space, &issued.access.grant_id, revision)
            .await,
        403,
    );
    status(
        f.source
            .revoke_network_access(&f.space, &issued.access.grant_id, revision - 1)
            .await,
        409,
    );
    let revoked = f
        .source
        .revoke_network_access(&f.space, &issued.access.grant_id, revision)
        .await?;
    status(
        f.target
            .network_access(&f.space, &issued.access.grant_id)
            .await,
        403,
    );
    status(
        f.source
            .network_access(&f.space, &issued.access.grant_id)
            .await,
        403,
    );
    status(
        f.source
            .start_network_access(
                &f.space,
                &issued.access.grant_id,
                NetworkAccessStart {
                    installation_id: f.source_device.device_id.clone(),
                    owner_id: random_id(),
                },
            )
            .await,
        403,
    );
    let mut reopened = f.store()?;
    let snapshot = reopened.network_policy_snapshot(&f.space, now()?)?;
    for grant in [&issued.access, &issued.connectivity, &issued.path] {
        assert!(
            verify_network_grant(&decode_network_grant(grant)?, &snapshot.verification()).is_err()
        );
    }
    let repeated = f
        .target
        .revoke_network_access(&f.space, &issued.access.grant_id, revoked.revision)
        .await?;
    assert_eq!(repeated.revision, revoked.revision);
    let mut request = f.fresh_request().await?;
    request.access_grant_id = issued.access.grant_id;
    status(f.target.issue_network_access(&f.space, request).await, 409);
    let second = f
        .target
        .issue_network_access(&f.space, f.fresh_request().await?)
        .await?;
    let revision = f.manager.space_details(&f.space).await?.space.revision;
    f.manager
        .revoke_network_access(&f.space, &second.access.grant_id, revision)
        .await?;
    status(
        f.source
            .network_access(&f.space, &second.access.grant_id)
            .await,
        403,
    );
    Ok(())
}

#[tokio::test]
async fn current_address_epoch_expiry_and_clock_rollback_invalidate_retained_graphs() -> Result {
    let f = Fixture::new().await?;
    let issued = f
        .target
        .issue_network_access(&f.space, f.request.clone())
        .await?;
    let before = f.manager.space_address_directory(&f.space).await?;
    f.manager
        .rename_space_address(
            &f.space,
            &f.target_device.device_id,
            SpaceAddressRename {
                expected_revision: before.revision,
                expected_address_epoch: f.request.expected_destination_address_epoch,
                name: "renamed-target".into(),
            },
        )
        .await?;
    status(
        f.source
            .network_access(&f.space, &issued.access.grant_id)
            .await,
        403,
    );
    status(
        f.target
            .start_network_access(
                &f.space,
                &issued.access.grant_id,
                NetworkAccessStart {
                    installation_id: f.target_device.device_id.clone(),
                    owner_id: random_id(),
                },
            )
            .await,
        403,
    );
    let mut reopened = f.store()?;
    let snapshot = reopened.network_policy_snapshot(&f.space, now()?)?;
    for grant in [&issued.access, &issued.connectivity, &issued.path] {
        assert!(
            verify_network_grant(&decode_network_grant(grant)?, &snapshot.verification()).is_err()
        );
    }
    assert!(matches!(
        reopened.network_policy_snapshot(&f.space, snapshot.verification().now_ms - 1),
        Err(StorageError::Conflict)
    ));
    // Explicit denial remains available even though old address readback fails.
    let revision = f.manager.space_details(&f.space).await?.space.revision;
    f.target
        .revoke_network_access(&f.space, &issued.access.grant_id, revision)
        .await?;
    let expiry = GrantClaims::decode_canonical(&decode_network_grant(&issued.access)?.claims)?
        .scope()
        .expires_at_ms;
    let at_expiry = reopened.network_policy_snapshot(&f.space, expiry)?;
    assert!(
        verify_network_grant(
            &decode_network_grant(&issued.access)?,
            &at_expiry.verification()
        )
        .is_err()
    );
    assert!(matches!(
        reopened.network_policy_snapshot(&f.space, expiry - 1),
        Err(StorageError::Conflict)
    ));
    Ok(())
}

#[tokio::test]
async fn actual_http_expiry_denies_readback_and_the_original_clock_cannot_roll_back() -> Result {
    let f = Fixture::new().await?;
    let mut request = f.request.clone();
    request.expires_at_unix_ms = now()? + 1000;
    let issued = f.target.issue_network_access(&f.space, request).await?;
    let signed = decode_network_grant(&issued.access)?;
    let expiry = GrantClaims::decode_canonical(&signed.claims)?
        .scope()
        .expires_at_ms;
    f.source
        .network_access(&f.space, &issued.access.grant_id)
        .await?;
    tokio::time::sleep(std::time::Duration::from_millis(
        expiry.saturating_sub(now()?) + 25,
    ))
    .await;
    status(
        f.source
            .network_access(&f.space, &issued.access.grant_id)
            .await,
        403,
    );
    status(
        f.source
            .start_network_access(
                &f.space,
                &issued.access.grant_id,
                NetworkAccessStart {
                    installation_id: f.source_device.device_id.clone(),
                    owner_id: random_id(),
                },
            )
            .await,
        403,
    );
    let mut reopened = f.store()?;
    let snapshot = reopened.network_policy_snapshot(&f.space, now()?)?;
    assert!(verify_network_grant(&signed, &snapshot.verification()).is_err());
    assert!(matches!(
        reopened.network_policy_snapshot(&f.space, expiry - 1),
        Err(StorageError::Conflict)
    ));
    Ok(())
}

#[tokio::test]
async fn concurrent_http_owner_starts_consume_each_endpoint_once_and_readback_never_resets_them()
-> Result {
    let f = Fixture::new().await?;
    let issued = f
        .target
        .issue_network_access(&f.space, f.request.clone())
        .await?;
    let source_start = NetworkAccessStart {
        installation_id: f.source_device.device_id.clone(),
        owner_id: random_id(),
    };
    status(
        f.manager
            .start_network_access(&f.space, &issued.access.grant_id, source_start.clone())
            .await,
        403,
    );
    status(
        f.stranger
            .start_network_access(&f.space, &issued.access.grant_id, source_start.clone())
            .await,
        403,
    );
    status(
        f.target
            .start_network_access(&f.space, &issued.access.grant_id, source_start.clone())
            .await,
        403,
    );
    // Two actual concurrent requests with the same public ID are still two
    // attempts. Only one may commit; an idempotent replay would refill quota.
    let (first, second) = tokio::join!(
        f.source
            .start_network_access(&f.space, &issued.access.grant_id, source_start.clone()),
        f.source
            .start_network_access(&f.space, &issued.access.grant_id, source_start.clone())
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    for result in [first, second] {
        if result.is_err() {
            status(result, 403);
        }
    }
    status(
        f.source
            .start_network_access(&f.space, &issued.access.grant_id, source_start)
            .await,
        403,
    );
    let read = f
        .source
        .network_access(&f.space, &issued.access.grant_id)
        .await?;
    exact_grants(&issued, &read)?;
    status(
        f.source
            .start_network_access(
                &f.space,
                &issued.access.grant_id,
                NetworkAccessStart {
                    installation_id: f.source_device.device_id.clone(),
                    owner_id: random_id(),
                },
            )
            .await,
        403,
    );
    let mut reopened = f.store()?;
    assert!(matches!(
        reopened.start_network_access(
            f.source.principal().ok_or("missing source login")?,
            &f.space,
            &issued.access.grant_id,
            NetworkAccessStart {
                installation_id: f.source_device.device_id.clone(),
                owner_id: random_id()
            },
            now()?
        ),
        Err(StorageError::Forbidden)
    ));
    let destination_start = NetworkAccessStart {
        installation_id: f.target_device.device_id.clone(),
        owner_id: random_id(),
    };
    status(
        f.source
            .start_network_access(&f.space, &issued.access.grant_id, destination_start.clone())
            .await,
        403,
    );
    f.target
        .start_network_access(&f.space, &issued.access.grant_id, destination_start.clone())
        .await?;
    status(
        f.target
            .start_network_access(&f.space, &issued.access.grant_id, destination_start)
            .await,
        403,
    );
    // Claiming does not alter any signed deadline, byte limit or graph digest.
    exact_grants(
        &issued,
        &f.target
            .network_access(&f.space, &issued.access.grant_id)
            .await?,
    )?;
    Ok(())
}
