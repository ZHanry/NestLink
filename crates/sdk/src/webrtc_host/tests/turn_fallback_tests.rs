use super::*;
use crate::{DeploymentTrust, LoginState};
use axum::{
    Json, Router,
    response::IntoResponse,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::Secret;
use nestlink_identity::turn::credential_request_transcript;
use nestlink_protocol::{
    API_BASE, ErrorCode, TurnCredentialsClaims,
    api::{ErrorResponse, HealthResponse, Principal, TurnBindingState, TurnCredentialRequest},
};
use reqwest::StatusCode;

#[derive(Clone, Copy)]
enum TurnReply {
    Capacity,
    Forbidden,
    BadSignature,
    Granted,
}

struct Fixture {
    sdk: Sdk,
    permit: VerifiedPermit,
    reservations: Arc<AtomicU32>,
    server: JoinHandle<()>,
    stop_owners: std::sync::Mutex<Vec<watch::Sender<Option<StopReason>>>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Fixture {
    /// The management fixture returns real issuer-signed permits and TURN
    /// credentials, so production SDK validation still runs at every boundary.
    async fn new(
        controller: &DeviceIdentity,
        host: &DeviceIdentity,
        paths: PathSet,
        reply: TurnReply,
    ) -> TestResult<Self> {
        Self::with_stun(controller, host, paths, reply, Vec::new()).await
    }

    async fn with_stun(
        controller: &DeviceIdentity,
        host: &DeviceIdentity,
        paths: PathSet,
        reply: TurnReply,
        stun_servers: Vec<std::net::SocketAddr>,
    ) -> TestResult<Self> {
        let signer = Arc::new(PermitSigner::generate());
        let mut claims = test_permit(controller, host)?.claims().clone();
        claims.paths = paths.to_wire();
        let signed = signer.sign(&claims)?;
        let permit = verify_permit(&signed.encode_to_vec(), &signer.public_key())?;
        let permit_response = serde_json::json!({
            "permit": URL_SAFE_NO_PAD.encode(signed.encode_to_vec()),
            "claims": claims,
        });
        let remote_response = serde_json::json!({
            "id": claims.session_id,
            "controller_device_id": claims.controller_device_id,
            "host_device_id": claims.host_device_id,
            "permissions": claims.permissions,
            "paths": claims.paths,
            "nonce": URL_SAFE_NO_PAD.encode([3; 32]),
            "policy_revision": claims.policy_revision,
            "expires_at_unix_ms": claims.expires_at_unix_ms,
            "status": "approved",
            "lease_sequence": claims.lease_sequence,
            "connection_generation": claims.connection_generation,
            "trust_revision": null,
            "password_revision": null,
        });
        let keys_response = serde_json::json!({
            "session_id": claims.session_id,
            "connection_generation": claims.connection_generation,
            "lease_sequence": claims.lease_sequence,
            "controller_public_key": URL_SAFE_NO_PAD.encode(controller.identity.public_key()),
            "host_public_key": URL_SAFE_NO_PAD.encode(host.identity.public_key()),
        });
        let reservations = Arc::new(AtomicU32::new(0));
        let reservation_count = reservations.clone();
        let turn_permit = permit.clone();
        let turn_signer = signer.clone();
        let path = format!("{API_BASE}/remote/{}", claims.session_id);
        let discovery = nestlink_protocol::api::NativeDiscoveryConfig {
            deployment_id: claims.deployment_id.clone(),
            stun_servers,
        };
        let app = Router::new()
            .route(
                &format!("{API_BASE}/network/discovery"),
                get(move || async move { Json(discovery) }),
            )
            .route(
                &format!("{path}/permit"),
                get(move || async move { Json(permit_response) }),
            )
            .route(&path, get(move || async move { Json(remote_response) }))
            .route(
                &format!("{path}/peer-keys"),
                get(move || async move { Json(keys_response) }),
            )
            .route(
                &format!("{path}/turn-peers"),
                get(|| async {
                    Json(TurnBindingState {
                        controller_allocation_id: None,
                        host_allocation_id: None,
                        controller_expires_at_unix_ms: None,
                        host_expires_at_unix_ms: None,
                        binding: None,
                    })
                }),
            )
            .route(
                &format!("{path}/turn-credentials"),
                post(move |Json(request): Json<TurnCredentialRequest>| {
                    let count = reservation_count.clone();
                    let permit = turn_permit.clone();
                    let signer = turn_signer.clone();
                    async move {
                        count.fetch_add(1, Ordering::AcqRel);
                        if matches!(reply, TurnReply::Capacity | TurnReply::Forbidden) {
                            let (status, code) = if matches!(reply, TurnReply::Capacity) {
                                (StatusCode::TOO_MANY_REQUESTS, ErrorCode::CapacityExceeded)
                            } else {
                                (StatusCode::FORBIDDEN, ErrorCode::PermissionRequired)
                            };
                            return (status, Json(ErrorResponse { code })).into_response();
                        }
                        let result = (|| -> TestResult<_> {
                            let p = permit.claims();
                            let transcript =
                                credential_request_transcript(p, &p.account_id, &request)?;
                            let claims = TurnCredentialsClaims {
                                schema_version: SCHEMA_VERSION,
                                deployment_id: p.deployment_id.clone(),
                                security_epoch: p.security_epoch,
                                session_id: p.session_id.clone(),
                                allocation_id: request.allocation_id,
                                device_id: request.device_id,
                                temporary_identity: p.controller_device_id.clone(),
                                purpose: TurnPurpose::BrowserWebRtc as i32,
                                node_id: id(20),
                                runtime_id: id(21),
                                runtime_generation: 1,
                                network_generation: request.network_generation,
                                connection_generation: p.connection_generation,
                                lease_sequence: p.lease_sequence,
                                permit_sha256: permit.digest().to_vec(),
                                request_sha256: digest(&transcript.encode_to_vec()).to_vec(),
                                grant_sequence: 1,
                                endpoint_revision: 1,
                                issued_at_unix_ms: unix_ms()?,
                                expires_at_unix_ms: p.expires_at_unix_ms,
                                username: "nestlink-test".into(),
                                realm: "nestlink".into(),
                                password: "A".repeat(43),
                                endpoints: vec!["turn:turn.example.test:3478?transport=udp".into()],
                                allow_loopback: false,
                            };
                            let mut signed = signer.sign_turn_credentials(&claims)?;
                            if matches!(reply, TurnReply::BadSignature) {
                                signed.signature[0] ^= 1;
                            }
                            Ok(signed)
                        })();
                        match result {
                            Ok(signed) => Json(signed).into_response(),
                            Err(_) => (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(ErrorResponse {
                                    code: ErrorCode::InternalError,
                                }),
                            )
                                .into_response(),
                        }
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let origin = url::Url::parse(&format!("http://{}", listener.local_addr()?))?;
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let sdk = Sdk {
            client: reqwest::Client::builder().no_proxy().build()?,
            origin,
            trust: DeploymentTrust {
                deployment_id: claims.deployment_id.clone(),
                permit_issuer: signer.public_key(),
            },
            health: HealthResponse {
                product: "NestLink".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                api_base: API_BASE.into(),
                alpn: nestlink_protocol::ALPN.into(),
                deployment_id: claims.deployment_id.clone(),
                security_epoch: claims.security_epoch,
                permit_issuer: URL_SAFE_NO_PAD.encode(signer.public_key()),
                node_policy_issuer: URL_SAFE_NO_PAD.encode(signer.public_key()),
            },
            login: Some(LoginState {
                principal: Principal {
                    account_id: claims.account_id.clone(),
                    session_id: id(22),
                    name: "test".into(),
                    is_admin: false,
                    access_expires: claims.expires_at_unix_ms / 1000,
                },
                access: Secret::from_text("A".repeat(43)),
                refresh: Secret::from_text("B".repeat(43)),
                generation: 1,
                refresh_expires: claims.expires_at_unix_ms / 1000 + 604800,
            }),
        };
        Ok(Self {
            sdk,
            permit,
            reservations,
            server,
            stop_owners: std::sync::Mutex::new(Vec::new()),
        })
    }

    fn setup(&self) -> TestResult<(SessionSetup, watch::Sender<Option<StopReason>>)> {
        let clock = RuntimeClock::default();
        let mut binding = test_binding(&self.permit)?;
        binding.local_paths = PathSet::from_wire(&self.permit.claims().paths)?;
        let path = if binding.local_paths.contains(Path::Direct) {
            Path::Direct
        } else {
            Path::Relay
        };
        let session = Session::activate(
            self.permit.clone(),
            binding,
            path,
            clock.monotonic_ms(),
            clock.sample()?,
        )?;
        let (owner, stop) = watch::channel(None);
        Ok((
            SessionSetup {
                session,
                path,
                role: EndpointRole::Host,
                clock,
                lifecycle: SessionLifecycle::new(stop),
            },
            owner,
        ))
    }

    async fn peer(&self, host: &DeviceIdentity) -> TestResult<WebRtcHostPeer> {
        let (setup, stop_owner) = self.setup()?;
        let peer =
            WebRtcHostPeer::new_with_turn(&self.sdk, host, self.permit.clone(), setup, |_| {
                Err(WebRtcHostError::Permit)
            })
            .await?;
        // Construction never opens capture; retain the actual lifecycle owner
        // so the production peer/path guard remains active during these tests.
        self.stop_owners
            .lock()
            .map_err(|_| io::Error::other("test lifecycle lock poisoned"))?
            .push(stop_owner);
        Ok(peer)
    }
}

fn offer(permit: &VerifiedPermit) -> SignalPayload {
    SignalPayload {
        ice: None,
        connection_generation: permit.claims().connection_generation,
        lease_sequence: permit.claims().lease_sequence,
        network_generation: 1,
        sequence: 1,
        candidates: Vec::new(),
        description: None,
    }
}

#[tokio::test]
async fn initial_native_ice_gatherer_actually_uses_stun_and_publishes_srflx() -> TestResult {
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    let permit = test_permit(&controller, &host)?;
    let stun = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let endpoint = format!("stun:{}", stun.local_addr()?);
    let responder = tokio::spawn(async move {
        let mut request = [0; 2048];
        loop {
            let (length, source) = stun.recv_from(&mut request).await?;
            if length < 20 || request[..2] != [0, 1] || request[4..8] != [0x21, 0x12, 0xa4, 0x42] {
                continue;
            }
            // RFC 8489 binding success with a synthetic public XOR-MAPPED
            // address. No external service or real NAT mapping is required.
            let mut response = vec![1, 1, 0, 12];
            response.extend_from_slice(&request[4..20]);
            response.extend_from_slice(&[0, 0x20, 0, 8, 0, 1]);
            response.extend_from_slice(&(45678_u16 ^ 0x2112).to_be_bytes());
            response.extend_from_slice(&[11 ^ 0x21, 0x12, 0xa4, 1 ^ 0x42]);
            stun.send_to(&response, source).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), std::io::Error>(())
    });
    let (peer, _, _, _) = make_peer(&permit, false, None, &[endpoint]).await?;
    let mut complete = peer.gathering_complete_promise().await;
    peer.set_local_description(peer.create_offer(None).await?)
        .await?;
    tokio::time::timeout(Duration::from_secs(5), complete.recv()).await?;
    let sdp = peer
        .local_description()
        .await
        .ok_or("missing local SDP")?
        .sdp;
    peer.close().await?;
    responder.abort();
    assert!(
        sdp.lines().any(|line| line.starts_with("a=candidate:")
            && line.contains("11.0.0.1")
            && line.contains(" typ srflx")),
        "the actual ICE gatherer did not publish a server-reflexive candidate"
    );
    Ok(())
}

#[tokio::test]
async fn stun_survives_turn_capacity_fallback_and_optional_turn_withdrawal() -> TestResult {
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    for reply in [TurnReply::Capacity, TurnReply::Granted] {
        let fixture = Fixture::with_stun(
            &controller,
            &host,
            PathSet::BOTH,
            reply,
            vec!["11.0.0.1:3478".parse()?],
        )
        .await?;
        let mut peer = fixture.peer(&host).await?;
        let configuration = peer.peer.get_configuration().await;
        assert!(
            configuration
                .ice_servers
                .iter()
                .any(|server| server.urls == vec!["stun:11.0.0.1:3478"])
        );
        peer.disable_optional_turn().await?;
        let configuration = peer.peer.get_configuration().await;
        assert_eq!(configuration.ice_servers.len(), 1);
        assert_eq!(
            configuration.ice_servers[0].urls,
            vec!["stun:11.0.0.1:3478"]
        );
        assert!(configuration.ice_servers[0].username.is_empty());
        assert!(configuration.ice_servers[0].credential.is_empty());
        peer.close().await?;
    }
    let fixture = Fixture::with_stun(
        &controller,
        &host,
        PathSet::RELAY,
        TurnReply::Granted,
        vec!["11.0.0.1:3478".parse()?],
    )
    .await?;
    let mut peer = fixture.peer(&host).await?;
    assert_eq!(
        peer.peer.get_configuration().await.ice_transport_policy,
        RTCIceTransportPolicy::Relay
    );
    assert!(
        peer.peer
            .get_configuration()
            .await
            .ice_servers
            .iter()
            .all(|server| server.urls.iter().all(|url| !url.starts_with("stun:")))
    );
    peer.close().await?;
    Ok(())
}

#[tokio::test]
async fn preferred_turn_capacity_outage_creates_direct_peer_but_relay_only_fails() -> TestResult {
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    for paths in [PathSet::BOTH, PathSet::RELAY] {
        let fixture = Fixture::new(&controller, &host, paths, TurnReply::Capacity).await?;
        let result = fixture.peer(&host).await;
        assert_eq!(fixture.reservations.load(Ordering::Acquire), 1);
        if paths == PathSet::BOTH {
            let mut peer = result?;
            assert!(peer.turn_credentials.is_none());
            assert!(peer.peer.get_configuration().await.ice_servers.is_empty());
            assert!(
                peer.validate_selected_pair(Path::Direct, "192.168.1.2:5000", "192.168.1.3:5001")
                    .is_ok()
            );
            assert!(
                peer.validate_selected_pair(Path::Relay, "8.8.8.8:5000", "1.1.1.1:5001")
                    .is_err()
            );
            peer.close().await?;
        } else {
            assert!(result.is_err());
        }
    }
    Ok(())
}

#[tokio::test]
async fn preferred_turn_permission_and_signature_errors_remain_fatal() -> TestResult {
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    for reply in [TurnReply::Forbidden, TurnReply::BadSignature] {
        let fixture = Fixture::new(&controller, &host, PathSet::BOTH, reply).await?;
        assert!(fixture.peer(&host).await.is_err());
        assert_eq!(fixture.reservations.load(Ordering::Acquire), 1);
    }
    Ok(())
}

#[tokio::test]
async fn lan_and_mdns_only_descriptions_disable_optional_turn_before_proof() -> TestResult {
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    for controller_sdp in [
        "a=candidate:1 1 UDP 1 192.168.1.3 5001 typ host\r\n",
        "a=candidate:1 1 UDP 1 76fa.local 5001 typ host\r\n",
    ] {
        let fixture = Fixture::new(&controller, &host, PathSet::BOTH, TurnReply::Granted).await?;
        let mut peer = fixture.peer(&host).await?;
        assert!(peer.turn_credentials.is_some());
        peer.prepare_turn_binding(
            &fixture.sdk,
            &host,
            &fixture.permit,
            &offer(&fixture.permit),
            controller_sdp,
            "a=candidate:1 1 UDP 1 192.168.1.2 5000 typ host\r\n",
        )
        .await?;
        assert!(peer.turn_credentials.is_none());
        assert!(peer.turn_binding_context.is_none());
        assert!(peer.turn_binding_claims.is_none());
        assert!(
            peer.peer
                .get_configuration()
                .await
                .ice_servers
                .iter()
                .all(|server| server.urls.is_empty()
                    && server.username.is_empty()
                    && server.credential.is_empty())
        );
        assert!(
            peer.validate_selected_pair(Path::Relay, "8.8.8.8:5000", "1.1.1.1:5001")
                .is_err()
        );
        assert!(!peer.proof_complete.load(Ordering::Acquire));
        peer.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn missing_initial_binding_falls_back_only_when_direct_is_permitted() -> TestResult {
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    for paths in [PathSet::BOTH, PathSet::RELAY] {
        let fixture = Fixture::new(&controller, &host, paths, TurnReply::Granted).await?;
        let mut peer = fixture.peer(&host).await?;
        let result = peer
            .prepare_turn_binding(
                &fixture.sdk,
                &host,
                &fixture.permit,
                &offer(&fixture.permit),
                "a=candidate:1 1 UDP 1 1.1.1.1 5001 typ host\r\n",
                "a=candidate:1 1 UDP 1 8.8.8.8 5000 typ host\r\n",
            )
            .await;
        if paths == PathSet::BOTH {
            result?;
            assert!(peer.turn_credentials.is_none());
            assert!(peer.turn_binding_context.is_none());
        } else {
            assert!(matches!(result, Err(WebRtcHostError::RelayUnavailable)));
            assert!(peer.turn_credentials.is_some());
        }
        peer.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn unsafe_nonhost_candidate_is_fatal_even_for_preferred_direct() -> TestResult {
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    let fixture = Fixture::new(&controller, &host, PathSet::BOTH, TurnReply::Granted).await?;
    let mut peer = fixture.peer(&host).await?;
    let result = peer
        .prepare_turn_binding(
            &fixture.sdk,
            &host,
            &fixture.permit,
            &offer(&fixture.permit),
            "a=candidate:1 1 UDP 1 192.168.1.3 5001 typ srflx\r\n",
            "a=candidate:1 1 UDP 1 8.8.8.8 5000 typ host\r\n",
        )
        .await;
    assert!(matches!(result, Err(WebRtcHostError::Contract(_))));
    peer.close().await?;
    Ok(())
}

#[tokio::test]
async fn selected_direct_discards_turn_and_selected_relay_cannot_downgrade() -> TestResult {
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    for selected in [Path::Direct, Path::Relay] {
        let fixture = Fixture::new(&controller, &host, PathSet::BOTH, TurnReply::Granted).await?;
        let mut peer = fixture.peer(&host).await?;
        peer.selected_path = selected;
        peer.selected_path_tx.send_replace(Some(selected));
        let result = peer.disable_optional_turn().await;
        if selected == Path::Direct {
            result?;
            // After direct selection, even a management outage cannot trigger
            // a TURN renewal or binding lookup on this connection.
            peer.refresh_turn_allocation(&fixture.sdk, &host, &fixture.permit, true)
                .await?;
            peer.maintain_turn_binding(&fixture.sdk, &host).await?;
            assert_eq!(fixture.reservations.load(Ordering::Acquire), 1);
            assert!(
                peer.validate_selected_pair(Path::Relay, "8.8.8.8:5000", "1.1.1.1:5001")
                    .is_err()
            );
        } else {
            assert!(matches!(result, Err(WebRtcHostError::RelayPathRequired)));
            assert!(peer.turn_credentials.is_some());
            assert!(!peer.peer.get_configuration().await.ice_servers.is_empty());
        }
        peer.close().await?;
    }
    Ok(())
}

#[test]
fn availability_fallback_does_not_swallow_authority_or_trust_errors() -> TestResult {
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    let permit = test_permit(&controller, &host)?;
    let unavailable: Result<(), _> = Err(WebRtcHostError::Sdk(SdkError::Timeout));
    assert!(optional_turn_result(&permit, true, unavailable)?.is_none());
    assert!(
        optional_turn_result::<()>(&permit, false, Err(WebRtcHostError::Sdk(SdkError::Timeout)))
            .is_err()
    );
    for error in [
        WebRtcHostError::Sdk(SdkError::Trust),
        WebRtcHostError::Sdk(SdkError::SignIn),
        WebRtcHostError::Sdk(SdkError::Api(
            StatusCode::FORBIDDEN,
            ErrorCode::PolicyRevoked,
        )),
        WebRtcHostError::Sdk(SdkError::Api(
            StatusCode::CONFLICT,
            ErrorCode::ReplayRejected,
        )),
        WebRtcHostError::TurnBinding,
        WebRtcHostError::Permit,
    ] {
        assert!(optional_turn_result::<()>(&permit, true, Err(error)).is_err());
    }
    Ok(())
}

#[test]
fn expired_permit_cannot_gain_a_new_direct_budget_from_turn_fallback() -> TestResult {
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    let mut claims = test_permit(&controller, &host)?.claims().clone();
    let now = unix_ms()?;
    claims.issued_at_unix_ms = now - 1000;
    claims.expires_at_unix_ms = now - 1;
    let signer = PermitSigner::generate();
    let expired = verify_permit(&signer.sign(&claims)?.encode_to_vec(), &signer.public_key())?;
    assert!(matches!(
        optional_turn_result::<()>(&expired, true, Err(WebRtcHostError::Sdk(SdkError::Timeout)),),
        Err(WebRtcHostError::Permit)
    ));
    Ok(())
}

#[tokio::test]
async fn optional_turn_operation_has_a_fixed_wait_budget() -> TestResult {
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    let permit = test_permit(&controller, &host)?;
    let started = Instant::now();
    let result = bounded_turn_operation::<()>(&permit, true, std::future::pending()).await;
    assert!(matches!(
        result,
        Err(WebRtcHostError::Sdk(SdkError::Timeout))
    ));
    assert!(started.elapsed() < Duration::from_secs(5));
    Ok(())
}
