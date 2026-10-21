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
use std::sync::atomic::AtomicU64;

#[tokio::test]
async fn trickle_answers_before_slow_stun_and_completes_a_signed_direct_connection() -> TestResult {
    for paths in [PathSet::DIRECT, PathSet::BOTH] {
        let controller = DeviceIdentity::generate();
        let host = DeviceIdentity::generate();
        let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let fixture = Fixture::with_features(
            &controller,
            &host,
            paths,
            TurnReply::Capacity,
            Vec::new(),
            &[nestlink_protocol::ice::TRICKLE_CAPABILITY],
        )
        .await?;
        let mut peer =
            test_host_peer_state(&fixture.permit, &host, controller.identity.public_key()).await?;
        peer.peer.close().await?;
        // Inject a local transport fixture at peer construction. Deployment
        // discovery continues to reject loopback/private STUN endpoints.
        let (native, video, audio, sender) = make_peer(
            &fixture.permit,
            false,
            None,
            &[format!("stun:{}", blackhole.local_addr()?)],
        )
        .await?;
        peer.peer = native;
        peer.video_track = video;
        peer.audio_track = audio;
        peer.video_sender = sender;
        let browser = make_browser_peer().await?;
        browser
            .create_data_channel(WEBRTC_CONTROL_LABEL, None)
            .await?;
        let mut browser_gathered = browser.gathering_complete_promise().await;
        browser
            .set_local_description(browser.create_offer(None).await?)
            .await?;
        let original = browser.local_description().await.ok_or("missing offer")?;
        let mut offer = SignalPayload {
            ice: Some(nestlink_protocol::ice::snapshot(&original.sdp, 1, false)?),
            connection_generation: fixture.permit.claims().connection_generation,
            lease_sequence: fixture.permit.claims().lease_sequence,
            network_generation: 1,
            sequence: 1,
            candidates: Vec::new(),
            description: Some(WebRtcDescription {
                kind: "offer".into(),
                sdp: nestlink_protocol::ice::without_candidates(&original.sdp),
                dtls_sha256: dtls_fingerprint(&original.sdp)?,
                in_reply_to_sequence: None,
            }),
        };
        tokio::time::timeout(
            Duration::from_secs(2),
            peer.publish_answer(&fixture.sdk, &host, &fixture.permit, offer.clone()),
        )
        .await??;
        assert_ne!(
            peer.peer.ice_gathering_state(),
            RTCIceGatheringState::Complete
        );
        assert!(peer.turn_binding_context.is_none());
        assert!(peer.turn_binding_claims.is_none());
        assert!(!peer.proof_complete.load(Ordering::Acquire));
        // Verify the actual published device signature before installing its SDP.
        let submission = fixture
            .signals
            .lock()
            .map_err(|_| "signal lock")?
            .drain(..)
            .next()
            .ok_or("missing early answer")?;
        let mut cursor = SignalCursor::new(&fixture.permit, &controller)?;
        let answer = crate::verify_peer_signal(
            &fixture.permit,
            &controller,
            nestlink_protocol::api::SignalView {
                account_id: fixture.permit.claims().account_id.clone(),
                public_key: URL_SAFE_NO_PAD.encode(host.identity.public_key()),
                submission,
            },
            &mut cursor,
        )?
        .ok_or("answer was not fresh")?;
        assert!(
            !answer
                .ice
                .as_ref()
                .ok_or("missing initial snapshot")?
                .end_of_candidates
        );
        // The unresolved STUN exchange stays alive; it has not been skipped to
        // make the timing assertion pass. It receives no response in this test.
        let mut request = [0; 512];
        let _ = tokio::time::timeout(Duration::from_secs(2), blackhole.recv_from(&mut request))
            .await??;
        let mut gathered = peer.peer.gathering_complete_promise().await;
        let _ = tokio::time::timeout(Duration::from_secs(8), gathered.recv()).await?;
        peer.publish_local_ice(&fixture.sdk, &host).await?;
        let completed = fixture
            .signals
            .lock()
            .map_err(|_| "signal lock")?
            .pop()
            .ok_or("missing completed answer")?;
        let completed = crate::verify_peer_signal(
            &fixture.permit,
            &controller,
            nestlink_protocol::api::SignalView {
                account_id: fixture.permit.claims().account_id.clone(),
                public_key: URL_SAFE_NO_PAD.encode(host.identity.public_key()),
                submission: completed,
            },
            &mut cursor,
        )?
        .ok_or("completion was not fresh")?;
        assert!(
            completed
                .ice
                .as_ref()
                .ok_or("missing completed snapshot")?
                .end_of_candidates
        );
        browser
            .set_remote_description(RTCSessionDescription::answer(
                answer
                    .description
                    .as_ref()
                    .ok_or("missing answer SDP")?
                    .sdp
                    .clone(),
            )?)
            .await?;
        let mut ice_cursor = nestlink_protocol::ice::IceSnapshotCursor::default();
        for snapshot in [answer.ice.as_ref(), completed.ice.as_ref()] {
            for candidate in ice_cursor.apply(snapshot.ok_or("missing snapshot")?)? {
                browser
                    .add_ice_candidate(RTCIceCandidateInit {
                        candidate: candidate.candidate,
                        sdp_mid: candidate.sdp_mid,
                        sdp_mline_index: Some(candidate.sdp_m_line_index),
                        username_fragment: Some(candidate.username_fragment),
                    })
                    .await?;
            }
        }
        let _ = tokio::time::timeout(Duration::from_secs(2), browser_gathered.recv()).await?;
        offer.sequence += 1;
        offer.ice = Some(nestlink_protocol::ice::snapshot(
            &browser
                .local_description()
                .await
                .ok_or("missing gathered offer")?
                .sdp,
            1,
            true,
        )?);
        peer.apply_remote_ice(&offer).await?;
        tokio::time::timeout(Duration::from_secs(5), async {
            while peer.peer.connection_state() != RTCPeerConnectionState::Connected
                || browser.connection_state() != RTCPeerConnectionState::Connected
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await?;
        assert_eq!(selected_ice_pair(&peer.peer).await?.0, Path::Direct);
        assert!(!peer.proof_complete.load(Ordering::Acquire));
        assert!(peer.media.is_none());
        peer.close().await?;
        browser.close().await?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum TurnReply {
    Capacity,
    Forbidden,
    BadSignature,
    Granted,
    ShortGrant,
    ShortGrantThenForbidden,
}

struct Fixture {
    sdk: Sdk,
    permit: VerifiedPermit,
    reservations: Arc<AtomicU32>,
    server: JoinHandle<()>,
    stop_owners: std::sync::Mutex<Vec<watch::Sender<Option<StopReason>>>>,
    binding_state: Arc<std::sync::Mutex<TurnBindingState>>,
    key_delay_ms: Arc<AtomicU64>,
    deny_peer_keys: Arc<AtomicBool>,
    key_reads: Arc<AtomicU32>,
    signals: Arc<std::sync::Mutex<Vec<nestlink_protocol::api::SignalSubmission>>>,
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
        Self::with_features(controller, host, paths, reply, stun_servers, &[]).await
    }

    async fn with_features(
        controller: &DeviceIdentity,
        host: &DeviceIdentity,
        paths: PathSet,
        reply: TurnReply,
        stun_servers: Vec<std::net::SocketAddr>,
        features: &[&str],
    ) -> TestResult<Self> {
        let signer = Arc::new(PermitSigner::generate());
        let mut claims = test_permit(controller, host)?.claims().clone();
        claims.paths = paths.to_wire();
        claims
            .required_capabilities
            .extend(features.iter().map(|v| (*v).to_owned()));
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
        let binding_state = Arc::new(std::sync::Mutex::new(TurnBindingState {
            controller_allocation_id: None,
            host_allocation_id: None,
            controller_expires_at_unix_ms: None,
            host_expires_at_unix_ms: None,
            binding: None,
        }));
        let state_response = binding_state.clone();
        let key_delay_ms = Arc::new(AtomicU64::new(0));
        let delay = key_delay_ms.clone();
        let deny_peer_keys = Arc::new(AtomicBool::new(false));
        let deny_keys = deny_peer_keys.clone();
        let key_reads = Arc::new(AtomicU32::new(0));
        let reads = key_reads.clone();
        let path = format!("{API_BASE}/remote/{}", claims.session_id);
        let signals = Arc::new(std::sync::Mutex::new(Vec::new()));
        let published = signals.clone();
        let discovery = nestlink_protocol::api::NativeDiscoveryConfig {
            deployment_id: claims.deployment_id.clone(),
            stun_servers,
        };
        let app = Router::new()
            .route(
                &format!("{path}/signals"),
                post(
                    move |Json(signal): Json<nestlink_protocol::api::SignalSubmission>| {
                        let published = published.clone();
                        async move {
                            published
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .push(signal);
                            StatusCode::NO_CONTENT
                        }
                    },
                ),
            )
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
                get(move || {
                    let response = keys_response.clone();
                    let delay = delay.clone();
                    let deny_keys = deny_keys.clone();
                    let reads = reads.clone();
                    async move {
                        reads.fetch_add(1, Ordering::AcqRel);
                        tokio::time::sleep(Duration::from_millis(delay.load(Ordering::Acquire)))
                            .await;
                        if deny_keys.load(Ordering::Acquire) {
                            return (
                                StatusCode::FORBIDDEN,
                                Json(ErrorResponse {
                                    code: ErrorCode::PermissionRequired,
                                }),
                            )
                                .into_response();
                        }
                        Json(response).into_response()
                    }
                }),
            )
            .route(
                &format!("{path}/turn-peers"),
                get(move || {
                    let state = state_response.clone();
                    async move {
                        let stored = state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let mut state = TurnBindingState {
                            controller_allocation_id: stored.controller_allocation_id.clone(),
                            host_allocation_id: stored.host_allocation_id.clone(),
                            controller_expires_at_unix_ms: stored.controller_expires_at_unix_ms,
                            host_expires_at_unix_ms: stored.host_expires_at_unix_ms,
                            binding: stored.binding.clone(),
                        };
                        drop(stored);
                        // Match production: filter at the state read, before
                        // the SDK's separately delayed peer-key request.
                        if state.binding.as_ref().is_some_and(|binding| {
                            TurnPeerBindingClaims::decode(binding.claims.as_slice()).is_ok_and(
                                |claims| {
                                    unix_ms().is_ok_and(|now| claims.expires_at_unix_ms <= now)
                                },
                            )
                        }) {
                            state.binding = None;
                        }
                        Json(state)
                    }
                }),
            )
            .route(
                &format!("{path}/turn-credentials"),
                post(move |Json(request): Json<TurnCredentialRequest>| {
                    let count = reservation_count.clone();
                    let permit = turn_permit.clone();
                    let signer = turn_signer.clone();
                    async move {
                        let sequence = count.fetch_add(1, Ordering::AcqRel) + 1;
                        if matches!(reply, TurnReply::Capacity | TurnReply::Forbidden)
                            || (matches!(reply, TurnReply::ShortGrantThenForbidden) && sequence > 1)
                        {
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
                                grant_sequence: u64::from(sequence),
                                endpoint_revision: 1,
                                issued_at_unix_ms: unix_ms()?,
                                expires_at_unix_ms: if matches!(
                                    reply,
                                    TurnReply::ShortGrant | TurnReply::ShortGrantThenForbidden
                                ) {
                                    p.expires_at_unix_ms.min(unix_ms()? + 4_000)
                                } else {
                                    p.expires_at_unix_ms
                                },
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
            binding_state,
            key_delay_ms,
            deny_peer_keys,
            key_reads,
            signals,
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

#[tokio::test]
async fn setup_wait_renews_short_signed_grants_without_waiting_for_peer_binding() -> TestResult {
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    let fixture = Fixture::new(&controller, &host, PathSet::BOTH, TurnReply::ShortGrant).await?;
    let mut peer = fixture.peer(&host).await?;
    let first = peer.turn_credentials.as_ref().ok_or("missing grant")?;
    let allocation = first.claims().allocation_id.clone();
    let first_expiry = first.claims().expires_at_unix_ms;
    let initial_permit = peer.current_permit().signed_envelope().to_vec();
    peer.maintain_turn_during_setup(
        &fixture.sdk,
        &host,
        tokio::time::sleep(Duration::from_secs(5)),
    )
    .await?;
    assert!(
        unix_ms()? > first_expiry,
        "wait did not cross the first node lease"
    );
    let renewed = peer
        .turn_credentials
        .as_ref()
        .ok_or("missing renewed grant")?;
    renewed.authorize(&fixture.permit, unix_ms()?)?;
    assert_eq!(renewed.claims().allocation_id, allocation);
    assert!(renewed.claims().grant_sequence > 1);
    assert!(fixture.reservations.load(Ordering::Acquire) > 1);
    assert_eq!(peer.current_permit().signed_envelope(), initial_permit);
    assert!(peer.turn_binding_context.is_none());
    assert!(!peer.proof_complete.load(Ordering::Acquire));
    assert!(peer.media.is_none());
    peer.close().await?;
    Ok(())
}

fn install_signed_binding(
    fixture: &Fixture,
    peer: &WebRtcHostPeer,
    controller: &DeviceIdentity,
    host: &DeviceIdentity,
    lifetime_ms: u64,
    corrupt_signature: bool,
) -> TestResult<TurnBindingContext> {
    let p = fixture.permit.claims();
    let credentials = peer
        .turn_credentials
        .as_ref()
        .ok_or("missing credentials")?
        .claims();
    let context = TurnBindingContext {
        controller_network_generation: 1,
        host_network_generation: peer.network_generation,
        controller_candidates: vec!["8.8.8.8:40000".into()],
        host_candidates: vec!["1.1.1.1:40001".into()],
    };
    let now = unix_ms()?;
    let claims = TurnPeerBindingClaims {
        schema_version: SCHEMA_VERSION,
        deployment_id: p.deployment_id.clone(),
        security_epoch: p.security_epoch,
        session_id: p.session_id.clone(),
        temporary_identity: p.controller_device_id.clone(),
        purpose: TurnPurpose::BrowserWebRtc as i32,
        controller_allocation_id: id(25),
        host_allocation_id: credentials.allocation_id.clone(),
        controller_device_id: p.controller_device_id.clone(),
        host_device_id: p.host_device_id.clone(),
        controller_key_sha256: p.controller_key_sha256.clone(),
        host_key_sha256: p.host_key_sha256.clone(),
        controller_network_generation: context.controller_network_generation,
        host_network_generation: context.host_network_generation,
        connection_generation: p.connection_generation,
        lease_sequence: p.lease_sequence,
        permit_sha256: fixture.permit.digest().to_vec(),
        controller_candidates: context.controller_candidates.clone(),
        host_candidates: context.host_candidates.clone(),
        issued_at_unix_ms: now,
        expires_at_unix_ms: (now + lifetime_ms).min(credentials.expires_at_unix_ms),
    };
    let mut signed = nestlink_protocol::SignedTurnPeerBinding {
        claims: claims.encode_to_vec(),
        controller_signature: controller.identity.sign_turn_peer_binding(&claims)?,
        host_signature: host.identity.sign_turn_peer_binding(&claims)?,
    };
    if corrupt_signature {
        signed.controller_signature[0] ^= 1;
    }
    *fixture.binding_state.lock().map_err(|_| "binding lock")? = TurnBindingState {
        controller_allocation_id: Some(claims.controller_allocation_id),
        host_allocation_id: Some(claims.host_allocation_id),
        controller_expires_at_unix_ms: Some(credentials.expires_at_unix_ms),
        host_expires_at_unix_ms: Some(credentials.expires_at_unix_ms),
        binding: Some(signed),
    };
    Ok(context)
}

#[tokio::test]
async fn complete_trickle_sets_require_the_existing_dual_signed_relay_binding() -> TestResult {
    for paths in [PathSet::BOTH, PathSet::RELAY] {
        let controller = DeviceIdentity::generate();
        let host = DeviceIdentity::generate();
        let fixture = Fixture::with_features(
            &controller,
            &host,
            paths,
            TurnReply::Granted,
            Vec::new(),
            &[nestlink_protocol::ice::TRICKLE_CAPABILITY],
        )
        .await?;
        let mut peer = fixture.peer(&host).await?;
        let expected = install_signed_binding(&fixture, &peer, &controller, &host, 5_000, false)?;
        let snapshot = |host: bool, complete: bool| -> TestResult<SignalPayload> {
            let address = if host {
                "1.1.1.1 40001"
            } else {
                "8.8.8.8 40000"
            };
            let fingerprint = std::iter::repeat_n("AB", 32).collect::<Vec<_>>().join(":");
            let sdp = format!(
                "v=0\r\na=fingerprint:sha-256 {fingerprint}\r\na=ice-ufrag:abc123\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:0\r\na=candidate:1 1 UDP 100 {address} typ srflx\r\n"
            );
            let signal = SignalPayload {
                ice: Some(nestlink_protocol::ice::snapshot(&sdp, 1, complete)?),
                connection_generation: fixture.permit.claims().connection_generation,
                lease_sequence: fixture.permit.claims().lease_sequence,
                network_generation: 1,
                sequence: 1,
                candidates: Vec::new(),
                description: Some(WebRtcDescription {
                    kind: if host { "answer" } else { "offer" }.into(),
                    sdp: nestlink_protocol::ice::without_candidates(&sdp),
                    dtls_sha256: vec![0xab; 32],
                    in_reply_to_sequence: host.then_some(1),
                }),
            };
            signal.validate(fixture.permit.claims())?;
            Ok(signal)
        };
        peer.local_ice_signal = Some(snapshot(true, true)?);
        peer.remote_ice_signal = Some(snapshot(false, false)?);
        peer.prepare_completed_ice_turn_binding(&fixture.sdk, &host)
            .await?;
        assert!(peer.turn_binding_context.is_none());
        assert!(peer.turn_binding_claims.is_none());
        peer.remote_ice_signal = Some(snapshot(false, true)?);
        peer.prepare_completed_ice_turn_binding(&fixture.sdk, &host)
            .await?;
        let actual = peer
            .turn_binding_context
            .as_ref()
            .ok_or("missing frozen context")?;
        assert_eq!(actual.controller_candidates, expected.controller_candidates);
        assert_eq!(actual.host_candidates, expected.host_candidates);
        assert!(peer.turn_binding_claims.is_some());
        assert!(!peer.proof_complete.load(Ordering::Acquire));
        assert!(peer.media.is_none());
        peer.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn verified_binding_expiring_during_peer_key_http_never_authorizes_relay() -> TestResult {
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    for paths in [PathSet::BOTH, PathSet::RELAY] {
        let fixture = Fixture::new(&controller, &host, paths, TurnReply::Granted).await?;
        let mut peer = fixture.peer(&host).await?;
        let permit_bytes = peer.current_permit().signed_envelope().to_vec();
        let context = install_signed_binding(&fixture, &peer, &controller, &host, 500, false)?;
        fixture.key_delay_ms.store(700, Ordering::Release);
        assert!(
            !peer
                .propose_turn_binding(&fixture.sdk, &host, &fixture.permit, &context, true)
                .await?
        );
        assert!(peer.turn_binding_claims.is_none());
        assert!(!peer.proof_complete.load(Ordering::Acquire));
        assert!(peer.media.is_none());
        assert!(
            fixture.key_reads.load(Ordering::Acquire) > 0,
            "response must expire during peer-key HTTP verification"
        );
        assert_eq!(peer.current_permit().signed_envelope(), permit_bytes);

        // A fresh, independently signed response can become ready; expiry
        // does not silently extend or reuse the old signed claims/allowlist.
        fixture.key_delay_ms.store(0, Ordering::Release);
        let fresh_context =
            install_signed_binding(&fixture, &peer, &controller, &host, 5_000, false)?;
        assert_eq!(
            context.controller_candidates,
            fresh_context.controller_candidates
        );
        assert!(
            peer.propose_turn_binding(&fixture.sdk, &host, &fixture.permit, &context, true)
                .await?
        );
        let ready = peer
            .turn_binding_claims
            .as_ref()
            .ok_or("missing fresh binding")?;
        assert!(ready.expires_at_unix_ms > unix_ms()?);
        peer.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn expired_binding_does_not_hide_forgery_or_management_denial() -> TestResult {
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    for deny_keys in [false, true] {
        let fixture = Fixture::new(&controller, &host, PathSet::BOTH, TurnReply::Granted).await?;
        let mut peer = fixture.peer(&host).await?;
        let context = install_signed_binding(&fixture, &peer, &controller, &host, 500, !deny_keys)?;
        fixture.key_delay_ms.store(700, Ordering::Release);
        fixture.deny_peer_keys.store(deny_keys, Ordering::Release);
        let result = peer
            .propose_turn_binding(&fixture.sdk, &host, &fixture.permit, &context, true)
            .await;
        assert!(optional_turn_result(&fixture.permit, true, result).is_err());
        assert!(peer.turn_binding_claims.is_none());
        assert!(!peer.proof_complete.load(Ordering::Acquire));
        peer.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn setup_renewal_does_not_swallow_management_denial() -> TestResult {
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    let fixture = Fixture::new(
        &controller,
        &host,
        PathSet::BOTH,
        TurnReply::ShortGrantThenForbidden,
    )
    .await?;
    let mut peer = fixture.peer(&host).await?;
    let result = peer
        .maintain_turn_during_setup(
            &fixture.sdk,
            &host,
            tokio::time::sleep(Duration::from_secs(5)),
        )
        .await;
    assert!(matches!(
        result,
        Err(WebRtcHostError::Sdk(SdkError::Api(
            StatusCode::FORBIDDEN,
            ErrorCode::PermissionRequired
        )))
    ));
    assert!(!peer.proof_complete.load(Ordering::Acquire));
    peer.close().await?;
    Ok(())
}

#[tokio::test]
async fn setup_renewal_wait_stops_on_cancellation_and_keeps_the_operation_budget() -> TestResult {
    let controller = DeviceIdentity::generate();
    let host = DeviceIdentity::generate();
    for cancel in [false, true] {
        let fixture =
            Fixture::new(&controller, &host, PathSet::BOTH, TurnReply::ShortGrant).await?;
        let mut peer = fixture.peer(&host).await?;
        let cancelled = peer.cancel_tx.clone();
        let trigger = async {
            if cancel {
                tokio::time::sleep(Duration::from_millis(100)).await;
                cancelled.send_replace(true);
            }
        };
        let started = Instant::now();
        let (result, ()) = tokio::join!(
            peer.maintain_turn_during_setup(
                &fixture.sdk,
                &host,
                tokio::time::timeout(Duration::from_millis(400), std::future::pending::<()>()),
            ),
            trigger,
        );
        if cancel {
            assert!(matches!(result, Err(WebRtcHostError::Closed)));
        } else {
            assert!(matches!(result, Ok(Err(_))));
        }
        assert!(started.elapsed() < Duration::from_secs(2));
        peer.close().await?;
    }
    Ok(())
}
