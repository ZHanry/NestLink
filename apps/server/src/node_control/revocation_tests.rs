//! Real HTTP revocation while ordinary database admission is saturated.
use super::*;
use nestlink_auth::{hash_password, random_id};
use nestlink_identity::nodes::NodeIdentity;
use nestlink_protocol::{NodeRole, api::NodeRegistration};
use std::io;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    state: AppState,
    client: reqwest::Client,
    origin: String,
    node: String,
    admin: String,
    member: String,
    server: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl Fixture {
    async fn new() -> TestResult<Self> {
        let mut store = Store::in_memory(&random_id())?;
        let vault = VaultKey::from_bytes([65; 32]);
        let password = "bounded-node-revocation-test-password";
        let dummy = hash_password("bounded-node-revocation-dummy-password")?;
        store.bootstrap_admin("admin", password)?;
        let admin = store.login("admin", password, None, now()?, &vault, &dummy)?;
        store.create_member(&admin.principal, "member", password)?;
        let member = store.login("member", password, None, now()?, &vault, &dummy)?;
        let node = random_id();
        store.register_node(
            &admin.principal,
            NodeRegistration {
                id: node.clone(),
                name: "bounded-revocation".into(),
                public_key: URL_SAFE_NO_PAD.encode(NodeIdentity::generate().public_key()),
                roles: vec![NodeRole::NodeRelay as i32],
                max_connections: 4,
                bytes_per_second: 1048576,
            },
        )?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("http://{}", listener.local_addr()?);
        let state = AppState::new(store, vault, PermitSigner::generate(), origin.clone(), false)?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()?;
        let app = router(state.clone());
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(Self {
            state,
            client,
            origin,
            node,
            admin: admin.access_token.expose().to_owned(),
            member: member.access_token.expose().to_owned(),
            server,
        })
    }
    async fn revoke(&self, token: Option<&str>) -> TestResult<StatusCode> {
        let request = self
            .client
            .delete(format!("{}/api/v3/nodes/{}", self.origin, self.node));
        let request = match token {
            Some(token) => request.bearer_auth(token),
            None => request,
        };
        Ok(request.send().await?.status())
    }
    fn node_is_live(&self) -> TestResult<bool> {
        let store = self
            .state
            .store
            .lock()
            .map_err(|_| io::Error::other("store poisoned"))?;
        Ok(store.node_challenge(&self.node, now_ms()?).is_ok())
    }
}

#[tokio::test]
async fn full_ordinary_workers_and_queue_cannot_block_authenticated_admin_node_revocation()
-> TestResult {
    let f = Fixture::new().await?;
    let mut ordinary = Vec::new();
    while let Ok(permit) = f.state.work.try_acquire() {
        ordinary.push(permit);
    }
    assert_eq!(ordinary.len(), 7);
    let mut queued = Vec::new();
    for _ in 0..8 {
        let mut request = Box::pin(f.state.work.acquire());
        assert!(
            tokio::time::timeout(Duration::from_millis(1), &mut request)
                .await
                .is_err()
        );
        queued.push(request);
    }
    assert_eq!(f.revoke(None).await?, StatusCode::UNAUTHORIZED);
    assert_eq!(
        f.revoke(Some(&"x".repeat(43))).await?,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(f.revoke(Some(&f.member)).await?, StatusCode::FORBIDDEN);
    assert!(f.node_is_live()?);
    assert_eq!(
        f.client
            .get(format!("{}/api/v3/nodes", f.origin))
            .bearer_auth(&f.admin)
            .send()
            .await?
            .status(),
        StatusCode::TOO_MANY_REQUESTS,
    );
    assert_eq!(f.revoke(Some(&f.admin)).await?, StatusCode::NO_CONTENT);
    assert!(!f.node_is_live()?);
    drop((queued, ordinary));
    Ok(())
}

#[tokio::test]
async fn saturated_revocation_lane_times_out_a_real_admin_without_a_detached_mutation()
-> TestResult {
    let f = Fixture::new().await?;
    let blocked = f
        .state
        .work
        .acquire_revocation()
        .await
        .map_err(|_| io::Error::other("admission closed"))?;
    assert_eq!(f.revoke(Some(&f.admin)).await?, StatusCode::TOO_MANY_REQUESTS);
    assert!(f.node_is_live()?);
    drop(blocked);
    tokio::task::yield_now().await;
    assert!(f.node_is_live()?);
    assert_eq!(f.revoke(Some(&f.admin)).await?, StatusCode::NO_CONTENT);
    assert!(!f.node_is_live()?);
    Ok(())
}
