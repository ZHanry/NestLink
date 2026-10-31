//! Real management HTTP/middleware, SQLite and SDK owners in the hosted VM.
use super::*;
use base64::Engine;
use nestlink_auth::{Secret, VaultKey, random_id};
use nestlink_identity::{
    PermitSigner,
    network::{NetworkVerification, verify_network_grant},
};
use nestlink_protocol::{
    api::NetworkIssueRequest,
    network::{Direction, IpPrefix, IpProtocol, NetworkRule},
    network_access::NetworkAccessRequest,
    spaces::{
        SpaceCreateRequest, SpaceDeviceJoin,
        addressing::{SpaceAddressIssue, SpaceAddressView},
    },
};
use nestlink_sdk::{DeploymentTrust, DeviceIdentity, network_management::decode_network_grant};
use nestlink_server::{AppState, router};
use nestlink_storage::Store;

mod https;

struct Server(
    tokio::task::JoinHandle<io::Result<()>>,
    Option<tokio::sync::oneshot::Sender<()>>,
);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}
pub(super) struct Fixture {
    _server: Server,
    _tunnel: Option<tokio::process::Child>,
    _private: tempfile::TempDir,
    pub directory: PathBuf,
    pub source: Sdk,
    pub target: Sdk,
    pub source_device: DeviceIdentity,
    pub target_device: DeviceIdentity,
    pub space: String,
    pub authority: [u8; 32],
    pub view: nestlink_protocol::network_access::NetworkAccessView,
    pub approved: [u8; 32],
    pub origin: String,
}
impl Fixture {
    pub async fn new(https_case: Option<&Path>) -> Result<Self> {
        // Secrets and the management database never enter the uploaded public
        // evidence directory, including if the coordinator terminates us.
        let private = tempfile::Builder::new()
            .prefix("nestlink-tun-online-private-")
            .tempdir_in(std::env::var("NESTLINK_TUN_NATIVE_PRIVATE_PARENT")?)?;
        let directory = private.path().join("original-installation");
        nestlink_platform_security::new_private_directory(&directory)?;
        let source_device = crate::identity(&directory)?;
        let target_device = DeviceIdentity::generate();
        let deployment = random_id();
        let signer = PermitSigner::generate();
        let issuer = signer.public_key();
        let authority = signer.network_authority_signer()?.public_key();
        let mut store = Store::open(&private.path().join("management.sqlite3"), &deployment)?;
        let password = Secret::from_text(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(nestlink_auth::random_bytes::<32>()),
        );
        let account = format!("lab-{}", random_id());
        store.bootstrap_admin(&account, password.expose())?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let (tunnel, origin) = if let Some(case) = https_case {
            let (tunnel, origin) = https::start(listener.local_addr()?, case).await?;
            (Some(tunnel), origin)
        } else {
            (None, format!("http://{}", listener.local_addr()?))
        };
        let app = router(AppState::new(
            store,
            VaultKey::from_bytes(nestlink_auth::random_bytes()),
            signer,
            origin.clone(),
            https_case.is_some(),
        )?)
        .layer(axum::middleware::from_fn(https::fixture_scope));
        let (shutdown, stopped) = tokio::sync::oneshot::channel();
        let server = Server(
            tokio::spawn(async move {
                axum::serve(
                    listener,
                    app.into_make_service_with_connect_info::<SocketAddr>(),
                )
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
            }),
            Some(shutdown),
        );
        let source = login(
            &origin,
            &deployment,
            issuer,
            &account,
            &password,
            https_case.is_none(),
        )
        .await?;
        let target = login(
            &origin,
            &deployment,
            issuer,
            &account,
            &password,
            https_case.is_none(),
        )
        .await?;
        let space = source
            .create_space(SpaceCreateRequest {
                name: "hosted original Windows packet owner".into(),
            })
            .await?
            .space_id;
        let source_address = endpoint(&source, &space, &source_device, "source").await?;
        let target_address = endpoint(&target, &space, &target_device, "target").await?;
        let directory_view = source.space_address_directory(&space).await?;
        let policy = source.space_details(&space).await?.space;
        let source_member = random_id();
        let target_member = random_id();
        for (sdk, device, id) in [
            (&source, &source_device, &source_member),
            (&target, &target_device, &target_member),
        ] {
            sdk.issue_network_membership(
                &space,
                &device.device_id,
                NetworkIssueRequest {
                    grant_id: id.clone(),
                    expected_policy_epoch: policy.policy_epoch,
                    expected_membership_epoch: 1,
                    expires_at_unix_ms: system_wall_ms()? + 45_000,
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
            source_membership_grant_id: source_member,
            destination_membership_grant_id: target_member,
            expected_revision: policy.revision,
            expected_policy_epoch: policy.policy_epoch,
            expected_directory_revision: directory_view.revision,
            expected_source_address_epoch: source_address.address_epoch,
            expected_destination_address_epoch: target_address.address_epoch,
            source_prefixes: prefixes(&source_address)?,
            destination_prefixes: prefixes(&target_address)?,
            rules: vec![NetworkRule {
                protocol: IpProtocol::Udp,
                direction: Direction::Inbound,
                ports: Some([443, 443]),
            }],
            byte_limit: 1024 * 1024,
            expires_at_unix_ms: system_wall_ms()? + 45_000,
        };
        let view = target.issue_network_access(&space, request).await?;
        let revoked = std::collections::BTreeSet::new();
        let approved = verify_network_grant(
            &decode_network_grant(&view.access)?,
            &NetworkVerification {
                authority_key: &authority,
                deployment_id: &deployment,
                space_id: &space,
                policy_epoch: policy.policy_epoch,
                now_ms: system_wall_ms()?,
                revoked_grant_ids: &revoked,
            },
        )?
        .digest();
        Ok(Self {
            _server: server,
            _tunnel: tunnel,
            _private: private,
            directory,
            source,
            target,
            source_device,
            target_device,
            space,
            authority,
            view,
            approved,
            origin,
        })
    }
    pub async fn finish(mut self) -> Result {
        drop(self.source);
        drop(self.target);
        if let Some(shutdown) = self._server.1.take() {
            let _ = shutdown.send(());
        }
        tokio::time::timeout(Duration::from_secs(5), &mut self._server.0).await???;
        if let Some(tunnel) = self._tunnel.as_mut() {
            if tunnel.try_wait()?.is_none() {
                tunnel.kill().await?;
            }
            let _ = tunnel.wait().await?;
        }
        self._private.close()?;
        Ok(())
    }
}
async fn login(
    origin: &str,
    deployment: &str,
    issuer: [u8; 32],
    account: &str,
    password: &Secret,
    allow_loopback: bool,
) -> Result<Sdk> {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut sdk = loop {
        match Sdk::connect(
            origin,
            DeploymentTrust {
                deployment_id: deployment.into(),
                permit_issuer: issuer,
            },
            allow_loopback,
        )
        .await
        {
            Ok(sdk) => break sdk,
            Err(error)
                if !allow_loopback
                    && Instant::now() < deadline
                    && match &error {
                        SdkError::Transport(_) | SdkError::Timeout => true,
                        SdkError::Api(status, _) => status.is_server_error(),
                        _ => false,
                    } =>
            {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(error) => return Err(error.into()),
        }
    };
    sdk.login(
        account.into(),
        Secret::from_text(password.expose().into()),
        None,
    )
    .await?;
    Ok(sdk)
}
async fn endpoint(
    sdk: &Sdk,
    space: &str,
    device: &DeviceIdentity,
    name: &str,
) -> Result<SpaceAddressView> {
    sdk.enroll(
        device,
        name.into(),
        "windows".into(),
        vec!["controller".into()],
        "direct_preferred".into(),
    )
    .await?;
    let revision = sdk.space_details(space).await?.space.revision;
    sdk.join_space_device(
        space,
        SpaceDeviceJoin {
            expected_revision: revision,
            expected_membership_epoch: 0,
            installation_id: device.device_id.clone(),
        },
    )
    .await?;
    let directory = sdk.space_address_directory(space).await?;
    let directory = sdk
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
    directory
        .addresses
        .into_iter()
        .find(|row| row.installation_id == device.device_id)
        .ok_or_else(|| io::Error::other("original online endpoint address missing").into())
}
fn prefixes(address: &SpaceAddressView) -> Result<Vec<IpPrefix>> {
    Ok(vec![
        IpPrefix {
            network: address.ipv4.parse()?,
            prefix_len: 32,
        },
        IpPrefix {
            network: address.ipv6.parse()?,
            prefix_len: 128,
        },
    ])
}
