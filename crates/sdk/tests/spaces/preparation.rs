//! A real handler commits, then loses its HTTP response body. The SDK must
//! recover only the same fixed pair through GET and retain the local pin.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_identity::VerifiedPermit;
use nestlink_protocol::{
    ErrorCode, Path, Permission,
    api::{ApprovalChoice, RemoteRequest},
};
use nestlink_sdk::network::routed::PinnedNetworkSpace;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
};

#[derive(Default)]
struct ResponseFault {
    lose: AtomicBool,
    post_fault: AtomicU8,
    posts: AtomicUsize,
    gets: AtomicUsize,
}
async fn lose_committed_response(
    axum::extract::State(fault): axum::extract::State<Arc<ResponseFault>>,
    mut request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> std::result::Result<axum::response::Response, (axum::http::StatusCode, &'static str)> {
    let preparation = request.uri().path().ends_with("/preparation");
    let post = preparation && request.method() == axum::http::Method::POST;
    if post {
        fault.posts.fetch_add(1, Ordering::SeqCst);
    }
    if preparation && request.method() == axum::http::Method::GET {
        fault.gets.fetch_add(1, Ordering::SeqCst);
    }
    let post_fault = if post {
        fault.post_fault.swap(0, Ordering::SeqCst)
    } else {
        0
    };
    if [1, 4, 5].contains(&post_fault) {
        use axum::response::IntoResponse;
        let (status, code) = match post_fault {
            1 => (
                axum::http::StatusCode::FORBIDDEN,
                ErrorCode::PermissionRequired,
            ),
            4 => (axum::http::StatusCode::CONFLICT, ErrorCode::ReplayRejected),
            _ => (axum::http::StatusCode::CONFLICT, ErrorCode::InvalidMessage),
        };
        return Ok((status, axum::Json(serde_json::json!({"code":code}))).into_response());
    }
    if post_fault == 2 {
        // Exercise the actual Store rejection of another business digest.
        // A fallback GET using the original query would succeed for the pair
        // already committed by the test, incorrectly hiding this denial.
        let body = std::mem::take(request.body_mut());
        let bytes = axum::body::to_bytes(body, 16_384).await.map_err(|_| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "bounded test request",
            )
        })?;
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "valid test request",
            )
        })?;
        value["permit_sha256"] = serde_json::json!(URL_SAFE_NO_PAD.encode([77; 32]));
        *request.body_mut() = axum::body::Body::from(serde_json::to_vec(&value).map_err(|_| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "test request encoding",
            )
        })?);
        request
            .headers_mut()
            .remove(axum::http::header::CONTENT_LENGTH);
    }
    let mut response = next.run(request).await;
    if post_fault == 3 && response.status().is_success() {
        // Keep the real handler and valid signatures, but return a mismatched
        // response binding. SDK validation must fail without any replacement GET.
        let body = std::mem::take(response.body_mut());
        let bytes = axum::body::to_bytes(body, 16_384).await.map_err(|_| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "bounded test response",
            )
        })?;
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "valid test response",
            )
        })?;
        value["request_id"] = serde_json::json!(random_id());
        *response.body_mut() =
            axum::body::Body::from(serde_json::to_vec(&value).map_err(|_| {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "test response encoding",
                )
            })?);
        response
            .headers_mut()
            .remove(axum::http::header::CONTENT_LENGTH);
    }
    if post && response.status().is_success() && fault.lose.swap(false, Ordering::SeqCst) {
        *response.body_mut() = axum::body::Body::from_stream(futures_util::stream::once(async {
            Err::<axum::body::Bytes, _>(std::io::Error::other("test-only committed response lost"))
        }));
    }
    Ok(response)
}

struct Fixture {
    _server: Server,
    owner: Sdk,
    controller_sdk: Sdk,
    host_sdk: Sdk,
    controller: DeviceIdentity,
    host: DeviceIdentity,
    permit: VerifiedPermit,
    space: SpaceView,
    pin: PinnedNetworkSpace,
    fault: Arc<ResponseFault>,
}
impl Fixture {
    async fn new() -> Result<Self> {
        let deployment = random_id();
        let signer = PermitSigner::generate();
        let issuer = signer.public_key();
        let mut store = Store::in_memory(&deployment)?;
        store.bootstrap_admin("owner", PASSWORD)?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("http://{}", listener.local_addr()?);
        let fault = Arc::new(ResponseFault::default());
        let app = router(AppState::new(
            store,
            VaultKey::from_bytes([64; 32]),
            signer,
            origin.clone(),
            false,
        )?)
        .layer(axum::middleware::from_fn_with_state(
            fault.clone(),
            lose_committed_response,
        ));
        let server = Server(tokio::spawn(async move {
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
        for name in ["controller", "host"] {
            owner
                .create_account(name.into(), Secret::from_text(PASSWORD.into()))
                .await?;
        }
        let mut controller_sdk = Sdk::connect(
            &origin,
            DeploymentTrust {
                deployment_id: deployment.clone(),
                permit_issuer: issuer,
            },
            true,
        )
        .await?;
        controller_sdk
            .login(
                "controller".into(),
                Secret::from_text(PASSWORD.into()),
                None,
            )
            .await?;
        let mut host_sdk = Sdk::connect(
            &origin,
            DeploymentTrust {
                deployment_id: deployment,
                permit_issuer: issuer,
            },
            true,
        )
        .await?;
        host_sdk
            .login("host".into(), Secret::from_text(PASSWORD.into()), None)
            .await?;
        let controller = DeviceIdentity::generate();
        let host = DeviceIdentity::generate();
        for (sdk, local) in [(&controller_sdk, &controller), (&host_sdk, &host)] {
            sdk.enroll(
                local,
                "pair endpoint".into(),
                "windows".into(),
                vec!["controller".into(), "host".into(), "vp8".into()],
                "direct_preferred".into(),
            )
            .await?;
        }
        let created = owner
            .create_space(SpaceCreateRequest {
                name: "private pair".into(),
            })
            .await?;
        let space_id = &created.space_id;
        for sdk in [&controller_sdk, &host_sdk] {
            let current = owner.space_details(space_id).await?.space;
            let invitation = owner
                .invite_to_space(
                    space_id,
                    SpaceInvitationRequest {
                        expected_revision: current.revision,
                        role: SpaceRole::Member,
                        target_account_id: Some(
                            sdk.principal()
                                .ok_or("missing principal")?
                                .account_id
                                .clone(),
                        ),
                        expires_at_unix_ms: current.observed_at_unix_ms + 60_000,
                    },
                )
                .await?;
            sdk.accept_space_invitation(
                space_id,
                &invitation.invitation.invitation_id,
                SpaceInvitationAcceptance {
                    token: invitation.token,
                },
            )
            .await?;
        }
        for (sdk, local) in [(&controller_sdk, &controller), (&host_sdk, &host)] {
            let current = sdk.space_details(space_id).await?.space;
            sdk.join_space_device(
                space_id,
                SpaceDeviceJoin {
                    expected_revision: current.revision,
                    expected_membership_epoch: 0,
                    installation_id: local.device_id.clone(),
                },
            )
            .await?;
        }
        let space = controller_sdk.space_details(space_id).await?.space;
        let pin = PinnedNetworkSpace::new(
            space.space_id.clone(),
            URL_SAFE_NO_PAD
                .decode(&space.authority_public_key)?
                .as_slice()
                .try_into()?,
        )?;
        let request = controller_sdk
            .create_remote(RemoteRequest {
                id: random_id(),
                controller_device_id: controller.device_id.clone(),
                host_device_id: host.device_id.clone(),
                permissions: vec![Permission::View as i32],
                path_mode: "direct_only".into(),
            })
            .await?;
        host_sdk
            .approve(
                &host,
                &request,
                ApprovalChoice {
                    approved: true,
                    permissions: vec![Permission::View as i32],
                    paths: vec![Path::Direct as i32],
                },
            )
            .await?;
        let permit = controller_sdk.permit(&request.id).await?;
        Ok(Self {
            _server: server,
            owner,
            controller_sdk,
            host_sdk,
            controller,
            host,
            permit,
            space,
            pin,
            fault,
        })
    }
}

#[tokio::test]
async fn ordinary_pair_preparation_recovers_real_lost_http_body_without_reissuing_or_renewing()
-> Result {
    let f = Fixture::new().await?;
    assert!(
        !f.controller_sdk
            .principal()
            .ok_or("missing controller")?
            .is_admin
    );
    assert!(!f.host_sdk.principal().ok_or("missing host")?.is_admin);
    let before = f.owner.space_audit(&f.space.space_id).await?.len();
    f.fault.lose.store(true, Ordering::SeqCst);
    let prepared = f
        .controller_sdk
        .prepare_network_remote(
            &f.pin,
            &f.controller,
            &f.permit,
            f.space.revision,
            f.space.policy_epoch,
        )
        .await?;
    assert_eq!(f.fault.posts.load(Ordering::SeqCst), 1);
    assert_eq!(f.fault.gets.load(Ordering::SeqCst), 1);
    assert_eq!(
        prepared.installation_ids(),
        [&f.controller.device_id[..], &f.host.device_id[..]]
    );
    assert_eq!(prepared.membership_epochs(), [1, 1]);
    assert_eq!(prepared.roles(), [SpaceRole::Member, SpaceRole::Member]);
    assert_eq!(
        prepared.connection_generation(),
        f.permit.claims().connection_generation
    );
    assert_eq!(prepared.permit_digest(), f.permit.digest());
    prepared
        .check_current(&f.controller_sdk, &f.controller, &f.permit)
        .await?;
    let peer = f
        .host_sdk
        .network_remote_preparation(
            &f.pin,
            &f.host,
            &f.permit,
            f.space.revision,
            f.space.policy_epoch,
        )
        .await?;
    assert_eq!(prepared.membership_grant_ids(), peer.membership_grant_ids());
    assert_eq!(prepared.expires_at_unix_ms(), peer.expires_at_unix_ms());
    let duplicate = f
        .controller_sdk
        .prepare_network_remote(
            &f.pin,
            &f.controller,
            &f.permit,
            f.space.revision,
            f.space.policy_epoch,
        )
        .await?;
    assert_eq!(
        duplicate.membership_grant_ids(),
        prepared.membership_grant_ids()
    );
    assert_eq!(
        duplicate.expires_at_unix_ms(),
        prepared.expires_at_unix_ms()
    );
    assert_eq!(
        f.owner.space_audit(&f.space.space_id).await?.len(),
        before + 2
    );
    forbidden(f.controller_sdk.network_policy(&f.space.space_id).await);
    forbidden(
        f.controller_sdk
            .network_membership_grant(&f.space.space_id, prepared.membership_grant_ids()[1])
            .await,
    );
    assert_eq!(
        f.controller_sdk
            .space_details(&f.space.space_id)
            .await?
            .devices
            .len(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn preparation_does_not_trust_directory_key_or_revive_a_revoked_fixed_pair() -> Result {
    let f = Fixture::new().await?;
    let prepared = f
        .controller_sdk
        .prepare_network_remote(
            &f.pin,
            &f.controller,
            &f.permit,
            f.space.revision,
            f.space.policy_epoch,
        )
        .await?;
    let wrong_pin = PinnedNetworkSpace::new(f.space.space_id.clone(), [99; 32])?;
    assert!(matches!(
        f.controller_sdk
            .network_remote_preparation(
                &wrong_pin,
                &f.controller,
                &f.permit,
                f.space.revision,
                f.space.policy_epoch
            )
            .await,
        Err(SdkError::Trust)
    ));
    assert!(matches!(
        f.controller_sdk
            .network_remote_preparation(
                &f.pin,
                &DeviceIdentity::generate(),
                &f.permit,
                f.space.revision,
                f.space.policy_epoch
            )
            .await,
        Err(SdkError::Trust)
    ));
    forbidden(
        f.owner
            .prepare_network_remote(
                &f.pin,
                &f.controller,
                &f.permit,
                f.space.revision,
                f.space.policy_epoch,
            )
            .await,
    );
    f.owner
        .revoke_network_membership_grant(
            &f.space.space_id,
            prepared.membership_grant_ids()[1],
            f.space.revision,
        )
        .await?;
    assert!(
        prepared
            .check_current(&f.controller_sdk, &f.controller, &f.permit)
            .await
            .is_err()
    );
    let current = f
        .controller_sdk
        .space_details(&f.space.space_id)
        .await?
        .space;
    let before = f.owner.space_audit(&f.space.space_id).await?.len();
    forbidden(
        f.controller_sdk
            .prepare_network_remote(
                &f.pin,
                &f.controller,
                &f.permit,
                current.revision,
                current.policy_epoch,
            )
            .await,
    );
    assert_eq!(f.owner.space_audit(&f.space.space_id).await?.len(), before);
    Ok(())
}

#[tokio::test]
async fn terminal_post_denial_or_wrong_binding_is_never_masked_by_successful_fixed_get() -> Result {
    let f = Fixture::new().await?;
    let prepared = f
        .controller_sdk
        .prepare_network_remote(
            &f.pin,
            &f.controller,
            &f.permit,
            f.space.revision,
            f.space.policy_epoch,
        )
        .await?;
    // Establish that GET really would return an admissible pair for the exact
    // original tuple. The following failures must remain visible nevertheless.
    prepared
        .check_current(&f.controller_sdk, &f.controller, &f.permit)
        .await?;
    let gets = f.fault.gets.load(Ordering::SeqCst);
    let audit = f.owner.space_audit(&f.space.space_id).await?.len();
    for post_fault in [1, 2, 3, 5] {
        let posts = f.fault.posts.load(Ordering::SeqCst);
        f.fault.post_fault.store(post_fault, Ordering::SeqCst);
        let result = f
            .controller_sdk
            .prepare_network_remote(
                &f.pin,
                &f.controller,
                &f.permit,
                f.space.revision,
                f.space.policy_epoch,
            )
            .await;
        match post_fault {
            1 | 2 => assert!(matches!(
                result,
                Err(SdkError::Api(
                    reqwest::StatusCode::FORBIDDEN,
                    ErrorCode::PermissionRequired
                ))
            )),
            3 => assert!(matches!(result, Err(SdkError::Trust))),
            _ => assert!(matches!(
                result,
                Err(SdkError::Api(
                    reqwest::StatusCode::CONFLICT,
                    ErrorCode::InvalidMessage
                ))
            )),
        }
        assert_eq!(f.fault.posts.load(Ordering::SeqCst), posts + 1);
        assert_eq!(f.fault.gets.load(Ordering::SeqCst), gets);
        assert_eq!(f.owner.space_audit(&f.space.space_id).await?.len(), audit);
    }
    // Only the exact Store conflict classification permits the same GET.
    f.fault.post_fault.store(4, Ordering::SeqCst);
    let recovered = f
        .controller_sdk
        .prepare_network_remote(
            &f.pin,
            &f.controller,
            &f.permit,
            f.space.revision,
            f.space.policy_epoch,
        )
        .await?;
    assert_eq!(f.fault.gets.load(Ordering::SeqCst), gets + 1);
    assert_eq!(
        recovered.membership_grant_ids(),
        prepared.membership_grant_ids()
    );
    assert_eq!(
        recovered.expires_at_unix_ms(),
        prepared.expires_at_unix_ms()
    );
    assert_eq!(f.owner.space_audit(&f.space.space_id).await?.len(), audit);
    Ok(())
}
