//! Typed SDK access to the administrator-only, revision-checked quota API.
use nestlink_auth::{Secret, VaultKey, random_id};
use nestlink_identity::PermitSigner;
use nestlink_protocol::service_plane::{
    ServiceQuotaLimitUpdate, ServiceQuotaScope, ServiceQuotaUsageQuery,
};
use nestlink_sdk::{DeploymentTrust, Sdk, SdkError};
use nestlink_server::{AppState, router};
use nestlink_storage::Store;
use tokio::net::TcpListener;

struct Server(tokio::task::JoinHandle<std::io::Result<()>>);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[tokio::test]
async fn service_quota_sdk_reads_updates_and_rejects_stale_revisions()
-> Result<(), Box<dyn std::error::Error>> {
    let deployment = random_id();
    let signer = PermitSigner::generate();
    let permit_issuer = signer.public_key();
    let mut store = Store::in_memory(&deployment)?;
    store.bootstrap_admin("admin", "service-quota-sdk-password")?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let app = router(AppState::new(
        store,
        VaultKey::from_bytes([91; 32]),
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
    let mut sdk = Sdk::connect(
        &origin,
        DeploymentTrust {
            deployment_id: deployment,
            permit_issuer,
        },
        true,
    )
    .await?;
    sdk.login(
        "admin".into(),
        Secret::from_text("service-quota-sdk-password".into()),
        None,
    )
    .await?;
    let account_id = sdk
        .accounts()
        .await?
        .into_iter()
        .find(|account| account.name == "admin")
        .ok_or("bootstrap admin missing from account list")?
        .id;
    let query = ServiceQuotaUsageQuery {
        scope: ServiceQuotaScope::Account,
        scope_key: account_id.clone(),
    };
    let original = sdk.service_quota_usage(query.clone()).await?;
    assert_eq!(original.limit_revision, 0);
    assert_eq!(original.scope_key, account_id);

    let changed = sdk
        .set_service_quota_limit(ServiceQuotaLimitUpdate {
            scope: query.scope,
            scope_key: query.scope_key.clone(),
            expected_revision: original.limit_revision,
            limit_bytes: 256 * 1024 * 1024,
        })
        .await?;
    assert_eq!(changed.limit_bytes, 256 * 1024 * 1024);
    assert_eq!(changed.limit_revision, 1);

    let stale_result = sdk
        .set_service_quota_limit(ServiceQuotaLimitUpdate {
            scope: query.scope,
            scope_key: query.scope_key.clone(),
            expected_revision: original.limit_revision,
            limit_bytes: 512 * 1024 * 1024,
        })
        .await;
    let stale = match stale_result {
        Err(problem) => problem,
        Ok(_) => return Err("a stale quota revision must be rejected".into()),
    };
    assert!(matches!(stale, SdkError::Api(status, _) if status.as_u16() == 409));
    let current = sdk.service_quota_usage(query).await?;
    assert_eq!(current.limit_bytes, 256 * 1024 * 1024);
    assert_eq!(current.limit_revision, 1);
    drop(server);
    Ok(())
}
