use nestlink_auth::{Secret, VaultKey, random_id};
use nestlink_identity::PermitSigner;
use nestlink_policy::PathSet;
use nestlink_protocol::{
    Path, Permission,
    api::{ApprovalChoice, RemoteRequest},
};
use nestlink_sdk::{
    DeploymentTrust, DeviceIdentity, Sdk,
    native::{AddressPolicy, NativeEndpoint, NativeSessionOptions, SessionEstablishError},
};
use nestlink_server::{AppState, router};
use nestlink_session::StopReason;
use nestlink_storage::Store;
use std::{net::IpAddr, time::Duration};
use tokio::sync::watch;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct Running(tokio::task::JoinHandle<()>);
impl Drop for Running {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn password() -> Secret {
    Secret::from_text("native-session-coordinator-password".into())
}

fn trust(deployment_id: &str, issuer: [u8; 32]) -> DeploymentTrust {
    DeploymentTrust {
        deployment_id: deployment_id.into(),
        permit_issuer: issuer,
    }
}

fn interface_address() -> Result<IpAddr> {
    if_addrs::get_if_addrs()?
        .into_iter()
        .find(|interface| {
            interface.is_oper_up()
                && !interface.is_loopback()
                && interface.ip().is_ipv4()
                && !interface.ip().is_unspecified()
                && !interface.ip().is_multicast()
        })
        .map(|interface| interface.ip())
        .ok_or_else(|| "no active non-loopback IPv4 interface for the loopback-free test".into())
}

#[tokio::test]
async fn coordinator_exchanges_current_signed_candidates_proves_and_stops_on_network_change()
-> Result {
    let deployment = random_id();
    let signer = PermitSigner::generate();
    let issuer = signer.public_key();
    let mut store = Store::in_memory(&deployment)?;
    store.bootstrap_admin("admin", password().expose())?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let app = router(AppState::new(
        store,
        VaultKey::from_bytes([51; 32]),
        signer,
        origin.clone(),
        false,
    )?);
    let _service = Running(tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    }));

    let mut controller_sdk = Sdk::connect(&origin, trust(&deployment, issuer), true).await?;
    controller_sdk
        .login("admin".into(), password(), None)
        .await?;
    controller_sdk
        .create_account("host-owner".into(), password())
        .await?;
    let mut host_sdk = Sdk::connect(&origin, trust(&deployment, issuer), true).await?;
    host_sdk
        .login("host-owner".into(), password(), None)
        .await?;

    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    controller_sdk
        .enroll(
            &controller,
            "controller".into(),
            "windows".into(),
            vec!["controller".into(), "vp8".into()],
            "direct_only".into(),
        )
        .await?;
    host_sdk
        .enroll(
            &host,
            "host".into(),
            "linux-x11".into(),
            vec!["host".into(), "vp8".into()],
            "direct_only".into(),
        )
        .await?;
    let request = controller_sdk
        .create_remote(RemoteRequest {
            id: random_id(),
            controller_device_id: controller.device_id.clone(),
            host_device_id: host.device_id.clone(),
            permissions: vec![Permission::View as i32, Permission::FileRead as i32],
            path_mode: "direct_only".into(),
        })
        .await?;
    host_sdk
        .approve(
            &host,
            &request,
            ApprovalChoice {
                approved: true,
                permissions: vec![Permission::View as i32, Permission::FileRead as i32],
                paths: vec![Path::Direct as i32],
            },
        )
        .await?;
    let permit = controller_sdk.permit(&request.id).await?;
    assert_eq!(
        host_sdk.host_permit(&host, &request.id).await?.digest(),
        permit.digest()
    );

    let address = interface_address()?;
    let prefix = format!("{address}/{}", if address.is_ipv4() { 32 } else { 128 });
    let policy = AddressPolicy::new(&[prefix])?;
    let controller_endpoint = NativeEndpoint::new(
        std::net::SocketAddr::new(address, 0),
        &controller,
        &host.identity.public_key(),
        permit.clone(),
        vec![],
        AddressPolicy::new(&[format!("{address}/32")])?,
    )?;
    let host_endpoint = NativeEndpoint::new(
        std::net::SocketAddr::new(address, 0),
        &host,
        &controller.identity.public_key(),
        permit,
        vec![],
        policy,
    )?;
    let legacy_addresses = [
        controller_endpoint.local_addr()?,
        host_endpoint.local_addr()?,
    ];

    let (cancel_owner, cancelled) = watch::channel(false);
    cancel_owner.send_replace(true);
    assert!(matches!(
        controller_endpoint
            .establish(
                &controller_sdk,
                &controller,
                NativeSessionOptions {
                    granted_permissions: vec![Permission::View, Permission::FileRead],
                    supported_capabilities: vec!["vp8".into()],
                    local_paths: PathSet::DIRECT,
                },
                &[],
                vec![],
                cancelled,
            )
            .await,
        Err(SessionEstablishError::Cancelled)
    ));

    let (_cancel_owner, cancel) = watch::channel(false);
    let (controller_session, host_session) = tokio::try_join!(
        controller_endpoint.establish(
            &controller_sdk,
            &controller,
            NativeSessionOptions {
                granted_permissions: vec![Permission::View, Permission::FileRead],
                supported_capabilities: vec!["vp8".into()],
                local_paths: PathSet::DIRECT,
            },
            &[],
            vec![],
            cancel.clone(),
        ),
        host_endpoint.establish(
            &host_sdk,
            &host,
            NativeSessionOptions {
                granted_permissions: vec![Permission::View, Permission::FileRead],
                supported_capabilities: vec!["vp8".into()],
                local_paths: PathSet::DIRECT,
            },
            &[],
            vec![],
            cancel,
        ),
    )?;
    assert_eq!(controller_session.candidate.path(), Path::Direct);
    assert_eq!(host_session.candidate.path(), Path::Direct);
    assert!(controller_session.uses_bilateral_ice());
    assert!(host_session.uses_bilateral_ice());
    let ice_addresses = [
        controller_session.candidate.address,
        host_session.candidate.address,
    ];
    let mut controller_session = controller_session;
    let host_session = host_session;
    let bytes = vec![47; 32_768];
    for index in 0..8 {
        host_session
            .channels
            .send(nestlink_transport_stream::Channel::FileRead, &bytes)
            .await?;
        let frame = tokio::time::timeout(
            Duration::from_secs(2),
            controller_session.channels.receive(),
        )
        .await
        .map_err(|error| format!("native ICE FileRead chunk {index} deadline: {error}"))??;
        assert_eq!(frame.channel, nestlink_transport_stream::Channel::FileRead);
        assert_eq!(frame.payload, bytes);
    }
    assert!(
        controller_session
            .channels
            .send(nestlink_transport_stream::Channel::Input, &[1])
            .await
            .is_err()
    );

    controller_endpoint.invalidate_network(2)?;
    let report = tokio::time::timeout(
        Duration::from_secs(2),
        controller_session.channels.wait_stopped(),
    )
    .await
    .map_err(|error| format!("native ICE controller network-change shutdown: {error}"))??;
    assert_eq!(report.reason, StopReason::NetworkChanged);
    let mut host_session = host_session;
    let host_report =
        tokio::time::timeout(Duration::from_secs(2), host_session.channels.wait_stopped())
            .await
            .map_err(|error| format!("native ICE peer close shutdown: {error}"))??;
    // A network-change close is explicitly retryable. The peer learns that
    // its transport was lost; it has not received an authority revocation.
    assert_eq!(host_report.reason, StopReason::TransportLost);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut controller_owner = nestlink_sdk::network::LegacyEndpoint::new(controller_endpoint);
    let mut host_owner = nestlink_sdk::network::LegacyEndpoint::new(host_endpoint);
    tokio::try_join!(
        controller_owner.close_and_wait(deadline),
        host_owner.close_and_wait(deadline)
    )?;
    for address in legacy_addresses.into_iter().chain(ice_addresses) {
        let _rebound = std::net::UdpSocket::bind(address)?;
    }
    Ok(())
}
