use nestlink_auth::{Secret, VaultKey, random_id};
use nestlink_identity::PermitSigner;
use nestlink_sdk::{DeploymentTrust, DeviceIdentity, Sdk};
use nestlink_server::{AppState, router};
use nestlink_storage::Store;
use std::time::{SystemTime, UNIX_EPOCH};

struct Running(tokio::task::JoinHandle<()>);
impl Drop for Running {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[tokio::test]
async fn sdk_registers_a_controller_only_browser_identity_with_bounded_expiry()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let deployment = random_id();
    let signer = PermitSigner::generate();
    let issuer = signer.public_key();
    let mut store = Store::in_memory(&deployment)?;
    store.bootstrap_admin("admin", "browser-sdk-test-password")?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let app = router(AppState::new(
        store,
        VaultKey::from_bytes([19; 32]),
        signer,
        origin.clone(),
        false,
    )?);
    let _server = Running(tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    }));
    let mut sdk = Sdk::connect(
        &origin,
        DeploymentTrust {
            deployment_id: deployment,
            permit_issuer: issuer,
        },
        true,
    )
    .await?;
    sdk.login(
        "admin".into(),
        Secret::from_text("browser-sdk-test-password".into()),
        None,
    )
    .await?;
    let identity = DeviceIdentity::generate();
    let lease = sdk
        .register_browser_endpoint(&identity, "Temporary browser".into(), "direct_only".into())
        .await?;
    assert_eq!(lease.device_id, identity.device_id);
    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
    assert!(lease.expires_at_unix_ms > now_ms);
    assert!(lease.expires_at_unix_ms <= now_ms + 600_000);
    let devices = sdk.devices().await?;
    let registered = devices
        .iter()
        .find(|entry| entry.device.id == identity.device_id)
        .ok_or_else(|| std::io::Error::other("browser endpoint is absent from the registry"))?;
    assert_eq!(registered.device.platform, "web");
    assert!(
        registered
            .device
            .capabilities
            .contains(&"controller".into())
    );
    assert!(!registered.device.capabilities.contains(&"host".into()));
    // An existing persistent browser installation upgrades its protocol support
    // under the same key; this must neither create a replacement nor add host.
    let persistent = DeviceIdentity::generate();
    sdk.enroll(
        &persistent,
        "Existing browser".into(),
        "web".into(),
        vec!["controller".into(), "vp8".into()],
        "direct_only".into(),
    )
    .await?;
    let descriptor = sdk
        .devices()
        .await?
        .into_iter()
        .find(|entry| entry.device.id == persistent.device_id)
        .ok_or_else(|| std::io::Error::other("persistent browser missing"))?
        .device;
    sdk.refresh_browser_features(&persistent, descriptor.clone())
        .await?;
    let upgraded = sdk
        .devices()
        .await?
        .into_iter()
        .find(|entry| entry.device.id == persistent.device_id)
        .ok_or_else(|| std::io::Error::other("upgraded browser missing"))?
        .device;
    assert_eq!(upgraded.id, descriptor.id);
    assert_eq!(upgraded.public_key, descriptor.public_key);
    assert!(
        upgraded
            .capabilities
            .iter()
            .any(|value| value == nestlink_protocol::ice::TRICKLE_CAPABILITY)
    );
    assert!(!upgraded.capabilities.iter().any(|value| value == "host"));
    let mut elevated = upgraded.clone();
    elevated.capabilities.push("host".into());
    assert!(
        sdk.refresh_browser_features(&persistent, elevated)
            .await
            .is_err()
    );
    let attacker = DeviceIdentity {
        device_id: persistent.device_id.clone(),
        identity: nestlink_identity::InstallationIdentity::generate(),
    };
    assert!(
        sdk.refresh_browser_features(&attacker, upgraded)
            .await
            .is_err()
    );
    Ok(())
}
