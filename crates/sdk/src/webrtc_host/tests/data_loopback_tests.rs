use super::*;
use nestlink_identity::digest;
use nestlink_protocol::{
    ClipboardWriteEffect, FILE_PAYLOAD_BYTES, FileReadErrorCode, FileReadManifest, FileRoot,
    FileWriteChunk, FileWriteErrorCode, FileWriteOpen, Permission, SCHEMA_VERSION,
    webrtc_data::{MAX_WEBRTC_DATA_FRAGMENT_BYTES, WebRtcDataBinding, WebRtcDataChannel},
};
use nestlink_remote::{
    ExternalChannelRuntime, RemoteError,
    clipboard::{
        ClipboardBinding, ClipboardConsent, ClipboardDevice, ClipboardDirection,
        ClipboardDirections, ClipboardReadClient, ClipboardRpcError, ClipboardServer,
        ClipboardShutdown, ClipboardWriteClient, ClipboardWriteOutcome,
    },
    files::{
        FileReadClient, FileReadConsent, FileReadDevice, FileReadRootListing, FileReadServer,
        FileReadSource, FileShutdown,
    },
    upload::{
        FileWriteClient, FileWriteConsent, FileWriteDestination, FileWriteDevice,
        FileWriteRootListing, FileWriteServer,
    },
};
use nestlink_session::StopReason;
use std::{
    collections::HashMap,
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
};
use webrtc::{
    data_channel::{RTCDataChannel, data_channel_message::DataChannelMessage},
    peer_connection::RTCPeerConnection,
};
use zeroize::Zeroizing;

const TEST_BUSINESS_QUEUE_CAPACITY: usize = 12;
const DATA_PERMISSIONS: [Permission; 5] = [
    Permission::View,
    Permission::FileRead,
    Permission::FileWrite,
    Permission::ClipboardRead,
    Permission::ClipboardWrite,
];

struct LoopbackPair {
    host: WebRtcHostPeer,
    controller_peer: Arc<RTCPeerConnection>,
    controller_control: Arc<RTCDataChannel>,
    controller_control_messages: mpsc::Receiver<Bytes>,
    controller_business: HashMap<WebRtcDataChannel, (Arc<RTCDataChannel>, mpsc::Receiver<Vec<u8>>)>,
    controller_cancel: watch::Sender<bool>,
    host_setup: Option<SessionSetup>,
    controller_setup: Option<SessionSetup>,
    _host_stop_owner: watch::Sender<Option<StopReason>>,
    _controller_stop_owner: watch::Sender<Option<StopReason>>,
}

impl LoopbackPair {
    async fn connected(
        permit: &VerifiedPermit,
        controller: &DeviceIdentity,
        host_identity: &DeviceIdentity,
    ) -> TestResult<Self> {
        let (host_setup, host_stop_owner) = test_setup(permit, EndpointRole::Host)?;
        let (controller_setup, controller_stop_owner) =
            test_setup(permit, EndpointRole::Controller)?;
        let mut host =
            test_host_peer_state(permit, host_identity, controller.identity.public_key()).await?;
        let controller_peer = make_browser_peer().await?;
        let controller_control = controller_peer
            .create_data_channel(WEBRTC_CONTROL_LABEL, None)
            .await?;

        let (controller_control_tx, controller_control_messages) =
            mpsc::channel(MAX_PENDING_CONTROL_MESSAGES);
        controller_control.on_message(Box::new(move |message| {
            let sender = controller_control_tx.clone();
            Box::pin(async move {
                if !message.is_string && sender.try_send(message.data).is_err() {
                    // The test only expects the small, bounded proof exchange.
                }
            })
        }));

        let mut controller_business = HashMap::new();
        for kind in data::authorized_channels(permit) {
            let channel = controller_peer
                .create_data_channel(kind.label(), None)
                .await?;
            let (sender, receiver) = mpsc::channel(TEST_BUSINESS_QUEUE_CAPACITY);
            channel.on_message(Box::new(move |message: DataChannelMessage| {
                let sender = sender.clone();
                Box::pin(async move {
                    if !message.is_string
                        && !message.data.is_empty()
                        && message.data.len() <= MAX_WEBRTC_DATA_FRAGMENT_BYTES
                    {
                        let _ = sender.try_send(message.data.to_vec());
                    }
                })
            }));
            controller_business.insert(kind, (channel, receiver));
        }

        let (state_tx, state_rx) = watch::channel(host.peer.connection_state());
        host.state_rx = state_rx;
        let (cancel_rx_tx, _) = watch::channel(false);
        drop(cancel_rx_tx);
        let (proof_tx, proof_messages) = mpsc::channel(MAX_PENDING_CONTROL_MESSAGES);
        let (input_tx, input_messages) = mpsc::channel(MAX_PENDING_INPUT_MESSAGES);
        let (display_tx, display_messages) = mpsc::channel(MAX_PENDING_DISPLAY_MESSAGES);
        host.proof_messages = proof_messages;
        host.input_messages = Some(input_messages);
        host.display_messages = Some(display_messages);
        let (controller_cancel, _) = watch::channel(false);
        install_peer_handlers(
            &host.peer,
            &host.control,
            &host.pending_data_channels,
            &host.cancel_tx,
            &state_tx,
            &host.permit_rx,
            PeerHandlerMessages {
                proof_messages: proof_tx,
                input_messages: input_tx,
                display_messages: display_tx,
                proof_complete: host.proof_complete.clone(),
                business_data_proof_complete: host.business_data_proof_complete.clone(),
                display_authorized: host.display_authorized.clone(),
                input_authorized: permit
                    .claims()
                    .permissions
                    .contains(&(Permission::Input as i32)),
            },
        );

        let offer = controller_peer.create_offer(None).await?;
        let mut browser_gathered = controller_peer.gathering_complete_promise().await;
        controller_peer.set_local_description(offer).await?;
        let _ = tokio::time::timeout(Duration::from_secs(10), browser_gathered.recv()).await?;
        let offer = controller_peer
            .local_description()
            .await
            .ok_or_else(|| io::Error::other("browser local offer missing"))?;
        host.peer.set_remote_description(offer).await?;

        let answer = host.peer.create_answer(None).await?;
        let mut host_gathered = host.peer.gathering_complete_promise().await;
        host.peer.set_local_description(answer).await?;
        let _ = tokio::time::timeout(Duration::from_secs(10), host_gathered.recv()).await?;
        let answer = host
            .peer
            .local_description()
            .await
            .ok_or_else(|| io::Error::other("host local answer missing"))?;
        controller_peer.set_remote_description(answer).await?;

        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let host_control_open = host
                    .control
                    .lock()
                    .await
                    .as_ref()
                    .is_some_and(|channel| channel.ready_state() == RTCDataChannelState::Open);
                let all_browser_channels_open = controller_business
                    .values()
                    .all(|(channel, _)| channel.ready_state() == RTCDataChannelState::Open);
                let all_host_channels_registered =
                    host.pending_data_channels.lock().await.len() == controller_business.len();
                if host_control_open
                    && controller_control.ready_state() == RTCDataChannelState::Open
                    && all_browser_channels_open
                    && all_host_channels_registered
                {
                    break;
                }
                if matches!(
                    host.peer.connection_state(),
                    RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed
                ) || matches!(
                    controller_peer.connection_state(),
                    RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed
                ) {
                    return Err(io::Error::other("loopback WebRTC connection failed"));
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok::<(), io::Error>(())
        })
        .await??;

        Ok(Self {
            host,
            controller_peer,
            controller_control,
            controller_control_messages,
            controller_business,
            controller_cancel,
            host_setup: Some(host_setup),
            controller_setup: Some(controller_setup),
            _host_stop_owner: host_stop_owner,
            _controller_stop_owner: controller_stop_owner,
        })
    }

    async fn prove(
        &mut self,
        permit: &VerifiedPermit,
        controller: &DeviceIdentity,
        host_identity: &DeviceIdentity,
    ) -> TestResult<(LeaseControl, LeaseControl)> {
        let mut controller_setup = self
            .controller_setup
            .take()
            .ok_or_else(|| io::Error::other("controller setup already consumed"))?;
        let mut host_setup = self
            .host_setup
            .take()
            .ok_or_else(|| io::Error::other("host setup already consumed"))?;
        let controller_transcript = controller_setup.session.proof_transcript();
        let controller_signature = controller.identity.prove(&controller_transcript)?;
        controller_setup.session.confirm_endpoint(
            EndpointRole::Controller,
            &controller.identity.public_key(),
            &controller_signature,
            controller_setup.clock.monotonic_ms(),
        )?;
        let opening = WebRtcControl::EndpointProof {
            schema_version: SCHEMA_VERSION,
            session_id: permit.claims().session_id.clone(),
            connection_generation: permit.claims().connection_generation,
            lease_sequence: permit.claims().lease_sequence,
            proof: NativeProof {
                transcript: Some(controller_transcript.clone()),
                signature: controller_signature,
                peer_transcript_signature: Vec::new(),
            },
        };
        self.controller_control
            .send(&Bytes::from(opening.encode_validated(permit.claims())?))
            .await?;

        {
            let mut proof = Box::pin(tokio::time::timeout(
                ENDPOINT_PROOF_TIMEOUT,
                self.host
                    .complete_native_proof(&mut host_setup, host_identity, permit),
            ));
            let middle = tokio::select! {
                result = &mut proof => {
                    result??;
                    return Err(io::Error::other("host proof completed before its challenge was answered").into());
                }
                message = tokio::time::timeout(Duration::from_secs(3), self.controller_control_messages.recv()) => {
                    message?.ok_or_else(|| io::Error::other("host proof response channel closed"))?
                }
            };
            let middle = WebRtcControl::decode_validated(&middle, permit.claims())?;
            let (host_transcript, host_signature, peer_signature) = match middle {
                WebRtcControl::EndpointProof { proof, .. } => (
                    proof
                        .transcript
                        .ok_or_else(|| io::Error::other("host transcript missing"))?,
                    proof.signature,
                    proof.peer_transcript_signature,
                ),
                _ => return Err(io::Error::other("host sent an unexpected proof message").into()),
            };
            matches_endpoint_transcript(&controller_transcript, &host_transcript)?;
            verify_endpoint_proof(
                &host_transcript,
                &host_identity.identity.public_key(),
                &host_signature,
            )?;
            verify_endpoint_proof(
                &controller_transcript,
                &host_identity.identity.public_key(),
                &peer_signature,
            )?;
            controller_setup.session.confirm_endpoint(
                EndpointRole::Host,
                &host_identity.identity.public_key(),
                &peer_signature,
                controller_setup.clock.monotonic_ms(),
            )?;
            let final_message = WebRtcControl::EndpointProof {
                schema_version: SCHEMA_VERSION,
                session_id: permit.claims().session_id.clone(),
                connection_generation: permit.claims().connection_generation,
                lease_sequence: permit.claims().lease_sequence,
                proof: NativeProof {
                    transcript: Some(host_transcript.clone()),
                    signature: controller.identity.prove(&host_transcript)?,
                    peer_transcript_signature: Vec::new(),
                },
            };
            self.controller_control
                .send(&Bytes::from(
                    final_message.encode_validated(permit.claims())?,
                ))
                .await?;
            proof.await??;
        }
        assert_eq!(host_setup.session.state(), SessionState::Active);
        assert_eq!(controller_setup.session.state(), SessionState::Active);
        self.host
            .business_data_proof_complete
            .store(true, Ordering::Release);

        self.host.clock = host_setup.clock.clone();
        let host_lease = take_proved_lease(host_setup)?;
        let controller_lease = take_proved_lease(controller_setup)?;
        self.host.lease = Some(host_lease.clone());
        if !permit.claims().is_setup() {
            self.host.publish_input_permit(permit)?;
        }
        self.host.proof_complete.store(true, Ordering::Release);
        Ok((host_lease, controller_lease))
    }

    async fn activate_setup_data(
        &mut self,
        management: &ManagedDataFixture,
        controller: &DeviceIdentity,
        host_identity: &DeviceIdentity,
        factory: HostDataFactory,
    ) -> TestResult<(LeaseControl, LeaseControl, VerifiedPermit)> {
        let permit = &management.permit;
        assert!(permit.claims().is_setup());
        let mut controller_setup = self
            .controller_setup
            .take()
            .ok_or_else(|| io::Error::other("controller setup already consumed"))?;
        self.host.setup = Some(
            self.host_setup
                .take()
                .ok_or_else(|| io::Error::other("host setup already consumed"))?,
        );
        let generation = permit.claims().connection_generation;
        self.host.media_factory = Some(Box::new(move |lease| {
            let display = Display {
                source: 1,
                logical: InputLayout {
                    left: 0,
                    top: 0,
                    width: 320,
                    height: 180,
                },
            };
            let epoch = VideoEpoch {
                layout: 1,
                connection: generation,
            };
            let capture = VideoController::attach(lease, EmptyCapture, epoch, vec![display])?;
            let video = HostVideoSource::new(
                capture,
                epoch,
                display,
                VideoConfig {
                    width: 320,
                    height: 180,
                    fps: 10,
                    bitrate_kbps: 500,
                },
            );
            Ok(HostMediaSources::new(video, None).with_data_factory(factory))
        }));

        let transcript = controller_setup.session.proof_transcript();
        let signature = controller.identity.prove(&transcript)?;
        controller_setup.session.confirm_endpoint(
            EndpointRole::Controller,
            &controller.identity.public_key(),
            &signature,
            controller_setup.clock.monotonic_ms(),
        )?;
        let opening = WebRtcControl::EndpointProof {
            schema_version: SCHEMA_VERSION,
            session_id: permit.claims().session_id.clone(),
            connection_generation: permit.claims().connection_generation,
            lease_sequence: permit.claims().lease_sequence,
            proof: NativeProof {
                transcript: Some(transcript.clone()),
                signature,
                peer_transcript_signature: Vec::new(),
            },
        };
        self.controller_control
            .send(&Bytes::from(opening.encode_validated(permit.claims())?))
            .await?;

        let control = self.controller_control.clone();
        let messages = &mut self.controller_control_messages;
        let controller_activation = async {
            let middle = tokio::time::timeout(Duration::from_secs(3), messages.recv())
                .await?
                .ok_or_else(|| io::Error::other("host setup proof response missing"))?;
            let WebRtcControl::EndpointProof { proof, .. } =
                WebRtcControl::decode_validated(&middle, permit.claims())?
            else {
                return Err(io::Error::other("host sent an unexpected setup proof message").into());
            };
            let host_transcript = proof
                .transcript
                .ok_or_else(|| io::Error::other("host setup proof transcript missing"))?;
            matches_endpoint_transcript(&transcript, &host_transcript)?;
            verify_endpoint_proof(
                &host_transcript,
                &host_identity.identity.public_key(),
                &proof.signature,
            )?;
            verify_endpoint_proof(
                &transcript,
                &host_identity.identity.public_key(),
                &proof.peer_transcript_signature,
            )?;
            controller_setup.session.confirm_endpoint(
                EndpointRole::Host,
                &host_identity.identity.public_key(),
                &proof.peer_transcript_signature,
                controller_setup.clock.monotonic_ms(),
            )?;
            let final_proof = WebRtcControl::EndpointProof {
                schema_version: SCHEMA_VERSION,
                session_id: permit.claims().session_id.clone(),
                connection_generation: permit.claims().connection_generation,
                lease_sequence: permit.claims().lease_sequence,
                proof: NativeProof {
                    transcript: Some(host_transcript.clone()),
                    signature: controller.identity.prove(&host_transcript)?,
                    peer_transcript_signature: Vec::new(),
                },
            };
            control
                .send(&Bytes::from(final_proof.encode_validated(permit.claims())?))
                .await?;
            let accepted = tokio::time::timeout(Duration::from_secs(3), messages.recv())
                .await?
                .ok_or_else(|| io::Error::other("host setup proof acceptance missing"))?;
            assert!(matches!(
                WebRtcControl::decode_validated(&accepted, permit.claims())?,
                WebRtcControl::EndpointProofAccepted { .. }
            ));
            let clock = controller_setup.clock.clone();
            let controller_lease = take_proved_lease(controller_setup)?;
            assert!(
                controller_lease
                    .check_media_binding(nestlink_transport_stream::Channel::Video, generation)
                    .is_err()
            );
            let bytes = tokio::time::timeout(Duration::from_secs(3), messages.recv())
                .await?
                .ok_or_else(|| io::Error::other("host setup activation signature missing"))?;
            let WebRtcControl::HostRenewalSignature {
                signature,
                lease_sequence: 2,
                ..
            } = WebRtcControl::decode_validated(&bytes, permit.claims())?
            else {
                return Err(io::Error::other("expected signed setup activation").into());
            };
            let view = management
                .controller_sdk
                .remote(&permit.claims().session_id)
                .await?;
            let started = clock.monotonic_ms();
            let running = management
                .controller_sdk
                .renew_permit(controller, &view, permit, signature)
                .await?;
            controller_lease.renew(running.clone(), started)?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((controller_lease, running))
        };
        // This is the production entry point: proof, signed setup activation,
        // media factory and HostDataRuntime initialization remain one path.
        let (host_result, controller_result) = tokio::join!(
            tokio::time::timeout(
                Duration::from_secs(10),
                self.host
                    .complete_endpoint_proof(Some(&management.host_sdk), host_identity),
            ),
            controller_activation,
        );
        host_result??;
        let (controller_lease, running) = controller_result?;
        assert!(!running.claims().is_setup());
        assert_eq!(running.claims().lease_sequence, 2);
        assert_ne!(running.digest(), permit.digest());
        assert_eq!(self.host.current_permit().digest(), running.digest());
        assert!(self.host.data_runtime.is_some());
        assert!(self.host.proof_complete.load(Ordering::Acquire));
        let host_lease =
            self.host.lease.clone().ok_or_else(|| {
                io::Error::other("production activation did not retain its lease")
            })?;
        Ok((host_lease, controller_lease, running))
    }
}

fn take_proved_lease(setup: SessionSetup) -> TestResult<LeaseControl> {
    let SessionSetup {
        session,
        path,
        clock,
        lifecycle,
        ..
    } = setup;
    Ok(LeaseControl::from_proved_session(
        session, path, clock, lifecycle,
    )?)
}

#[tokio::test]
async fn preproof_business_payload_is_rejected_and_never_buffered() -> TestResult {
    let controller = DeviceIdentity::generate();
    let host_identity = DeviceIdentity::generate();
    let permit =
        test_permit_with_permissions(&controller, &host_identity, DATA_PERMISSIONS.to_vec())?;
    let pair = LoopbackPair::connected(&permit, &controller, &host_identity).await?;
    let business_channel = pair
        .controller_business
        .get(&WebRtcDataChannel::FileRead)
        .ok_or_else(|| io::Error::other("file-read channel missing"))?
        .0
        .clone();

    business_channel
        .send(&Bytes::from_static(b"before-proof"))
        .await?;
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut cancel = pair.host.cancel_tx.subscribe();
        while !*cancel.borrow() {
            cancel
                .changed()
                .await
                .map_err(|_| io::Error::other("cancel watch closed"))?;
        }
        Ok::<(), io::Error>(())
    })
    .await??;
    tokio::time::timeout(Duration::from_secs(3), async {
        while pair.host.peer.connection_state() != RTCPeerConnectionState::Closed {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    assert!(
        !pair
            .host
            .business_data_proof_complete
            .load(Ordering::Acquire)
    );
    let pending = pair
        .host
        .pending_data_channels
        .lock()
        .await
        .remove(&WebRtcDataChannel::FileRead)
        .ok_or_else(|| io::Error::other("registered channel disappeared"))?;
    let (_, mut received) = pending.into_parts();
    assert!(matches!(
        received.try_recv(),
        Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected)
    ));
    assert!(pair.host.data_runtime.is_none());
    Ok(())
}

#[derive(Clone)]
struct ServiceState {
    file_read_root: String,
    file_write_root: String,
    source: Arc<Vec<u8>>,
    read_allowed: Arc<AtomicBool>,
    write_allowed: Arc<AtomicBool>,
    clipboard_binding: ClipboardBinding,
    clipboard_read_allowed: Arc<AtomicBool>,
    clipboard_write_allowed: Arc<AtomicBool>,
    clipboard_text: Arc<Mutex<String>>,
    uploaded: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    read_device_drops: Arc<AtomicUsize>,
    write_device_drops: Arc<AtomicUsize>,
    clipboard_closed: Arc<AtomicBool>,
}

struct ReadConsent(Arc<AtomicBool>);
impl FileReadConsent for ReadConsent {
    fn check(&self) -> io::Result<()> {
        if self.0.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "test local file-read consent denied",
            ))
        }
    }
}

struct MemoryReadSource {
    bytes: Arc<Vec<u8>>,
    consent: Arc<dyn FileReadConsent>,
}
impl FileReadSource for MemoryReadSource {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        self.consent.clone()
    }

    fn describe(
        &mut self,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<FileReadManifest> {
        authorized()?;
        self.consent.check()?;
        Ok(FileReadManifest {
            size: self.bytes.len() as u64,
            sha256: digest(&self.bytes).to_vec(),
            offset: 0,
        })
    }

    fn read_chunk(
        &mut self,
        offset: u64,
        maximum: usize,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Vec<u8>> {
        authorized()?;
        self.consent.check()?;
        let start = usize::try_from(offset)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "offset too large"))?;
        let end = start
            .checked_add(maximum)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "read out of bounds"))?;
        Ok(self.bytes[start..end].to_vec())
    }

    fn verify(
        &mut self,
        original: &FileReadManifest,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        authorized()?;
        self.consent.check()?;
        if original.size != self.bytes.len() as u64 || original.sha256 != digest(&self.bytes) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "source changed"));
        }
        Ok(())
    }
}

struct MemoryReadDevice(ServiceState);
impl Drop for MemoryReadDevice {
    fn drop(&mut self) {
        self.0.read_device_drops.fetch_add(1, Ordering::AcqRel);
    }
}
impl FileReadDevice for MemoryReadDevice {
    fn list_roots(
        &mut self,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<FileReadRootListing> {
        authorized()?;
        let consent: Arc<dyn FileReadConsent> = Arc::new(ReadConsent(self.0.read_allowed.clone()));
        Ok(FileReadRootListing {
            roots: vec![FileRoot {
                root_id: self.0.file_read_root.clone(),
                display_name: "Loopback read fixture".into(),
            }],
            consent,
        })
    }

    fn open(&mut self, root: &str, relative_path: &str) -> io::Result<Box<dyn FileReadSource>> {
        if root != self.0.file_read_root || relative_path != "source.bin" {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "test source not found",
            ));
        }
        let consent: Arc<dyn FileReadConsent> = Arc::new(ReadConsent(self.0.read_allowed.clone()));
        Ok(Box::new(MemoryReadSource {
            bytes: self.0.source.clone(),
            consent,
        }))
    }
}

struct MemoryWriteDestination {
    state: ServiceState,
    path: String,
    bytes: Vec<u8>,
    published: bool,
    file_closed: bool,
    temporary_removed: bool,
}
impl FileWriteDestination for MemoryWriteDestination {
    fn consent(&self) -> Arc<dyn FileWriteConsent> {
        self.state.write_allowed.clone()
    }

    fn status(&self) -> nestlink_protocol::FileWriteState {
        nestlink_protocol::FileWriteState {
            confirmed_bytes: self.bytes.len() as u64,
            published: self.published,
            file_closed: self.file_closed,
            temporary_removed: self.temporary_removed,
            directory_synced: self.published,
            poisoned: false,
        }
    }

    fn prepare(&mut self, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        authorized()?;
        FileWriteConsent::check(self.state.write_allowed.as_ref())?;
        self.bytes.clear();
        self.file_closed = false;
        self.temporary_removed = false;
        Ok(())
    }

    fn write(
        &mut self,
        chunk: &FileWriteChunk,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        authorized()?;
        FileWriteConsent::check(self.state.write_allowed.as_ref())?;
        if chunk.offset != self.bytes.len() as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "write offset differs",
            ));
        }
        self.bytes.extend_from_slice(&chunk.data);
        Ok(())
    }

    fn finish(&mut self, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        authorized()?;
        FileWriteConsent::check(self.state.write_allowed.as_ref())?;
        self.state
            .uploaded
            .lock()
            .map_err(|_| io::Error::other("upload map poisoned"))?
            .insert(self.path.clone(), self.bytes.clone());
        self.published = true;
        self.file_closed = true;
        self.temporary_removed = true;
        Ok(())
    }

    fn cleanup(&mut self) -> io::Result<()> {
        if !self.published {
            self.bytes.clear();
        }
        self.file_closed = true;
        self.temporary_removed = true;
        Ok(())
    }
}

struct MemoryWriteDevice(ServiceState);
impl Drop for MemoryWriteDevice {
    fn drop(&mut self) {
        self.0.write_device_drops.fetch_add(1, Ordering::AcqRel);
    }
}
impl FileWriteDevice for MemoryWriteDevice {
    fn list_roots(&mut self) -> io::Result<FileWriteRootListing> {
        let consent: Arc<dyn FileWriteConsent> = self.0.write_allowed.clone();
        Ok(FileWriteRootListing {
            roots: vec![FileRoot {
                root_id: self.0.file_write_root.clone(),
                display_name: "Loopback write fixture".into(),
            }],
            consent,
        })
    }

    fn build(
        &mut self,
        open: &FileWriteOpen,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Box<dyn FileWriteDestination>> {
        authorized()?;
        FileWriteConsent::check(self.0.write_allowed.as_ref())?;
        if open.root_id != self.0.file_write_root || open.path != "target.bin" {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "test destination not found",
            ));
        }
        Ok(Box::new(MemoryWriteDestination {
            state: self.0.clone(),
            path: open.path.clone(),
            bytes: Vec::new(),
            published: false,
            file_closed: false,
            temporary_removed: true,
        }))
    }
}

struct ClipboardAllowed(Arc<AtomicBool>);
impl ClipboardConsent for ClipboardAllowed {
    fn check_until(&self, deadline: Instant) -> io::Result<()> {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "clipboard deadline expired",
            ));
        }
        if self.0.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "clipboard consent denied",
            ))
        }
    }
}

struct ClipboardDeviceFixture(ServiceState);
impl ClipboardDevice for ClipboardDeviceFixture {
    fn binding(&self) -> &ClipboardBinding {
        &self.0.clipboard_binding
    }

    fn consent(&self, direction: ClipboardDirection) -> Arc<dyn ClipboardConsent> {
        Arc::new(ClipboardAllowed(match direction {
            ClipboardDirection::Read => self.0.clipboard_read_allowed.clone(),
            ClipboardDirection::Write => self.0.clipboard_write_allowed.clone(),
        }))
    }

    fn read_text(
        &mut self,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Option<String>> {
        authorized()?;
        if !self.0.clipboard_read_allowed.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "read consent revoked",
            ));
        }
        Ok(Some(
            self.0
                .clipboard_text
                .lock()
                .map_err(|_| io::Error::other("clipboard fixture poisoned"))?
                .clone(),
        ))
    }

    fn write_text(
        &mut self,
        text: &str,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> ClipboardWriteOutcome {
        if let Err(error) = authorized() {
            return ClipboardWriteOutcome {
                effect: ClipboardWriteEffect::ClipboardWriteNotApplied,
                error: Some(error),
            };
        }
        if !self.0.clipboard_write_allowed.load(Ordering::Acquire) {
            return ClipboardWriteOutcome {
                effect: ClipboardWriteEffect::ClipboardWriteNotApplied,
                error: Some(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "write consent revoked",
                )),
            };
        }
        match self.0.clipboard_text.lock() {
            Ok(mut current) => *current = text.into(),
            Err(_) => {
                return ClipboardWriteOutcome {
                    effect: ClipboardWriteEffect::ClipboardWriteNotApplied,
                    error: Some(io::Error::other("clipboard fixture poisoned")),
                };
            }
        }
        ClipboardWriteOutcome {
            effect: ClipboardWriteEffect::ClipboardWriteApplied,
            error: authorized().err(),
        }
    }

    fn close(&mut self) -> io::Result<()> {
        self.0.clipboard_closed.store(true, Ordering::Release);
        Ok(())
    }

    fn cleanup_complete(&self) -> bool {
        self.0.clipboard_closed.load(Ordering::Acquire)
    }
}

struct AlwaysClipboardConsent;
impl ClipboardConsent for AlwaysClipboardConsent {
    fn check_until(&self, deadline: Instant) -> io::Result<()> {
        if Instant::now() < deadline {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "clipboard deadline expired",
            ))
        }
    }
}

struct LoopbackDataOwner {
    file_read: Option<FileReadServer>,
    file_write: Option<FileWriteServer>,
    clipboard: Option<ClipboardServer>,
    shutdown_calls: Arc<AtomicUsize>,
}
impl HostDataOwner for LoopbackDataOwner {
    fn shutdown<'a>(
        &'a mut self,
        reason: StopReason,
    ) -> Pin<Box<dyn Future<Output = Result<(), RemoteError>> + Send + 'a>> {
        Box::pin(async move {
            self.shutdown_calls.fetch_add(1, Ordering::AcqRel);
            if let Some(server) = self.file_read.as_mut() {
                if server.shutdown(reason).await? != FileShutdown::Finished {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "FileRead cleanup pending",
                    )
                    .into());
                }
                self.file_read.take();
            }
            if let Some(server) = self.file_write.as_mut() {
                if server.shutdown(reason).await? != FileShutdown::Finished {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "FileWrite cleanup pending",
                    )
                    .into());
                }
                self.file_write.take();
            }
            if let Some(server) = self.clipboard.as_mut() {
                if server.shutdown(reason).await? != ClipboardShutdown::Finished {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "clipboard cleanup pending",
                    )
                    .into());
                }
                self.clipboard.take();
            }
            Ok(())
        })
    }
}

#[derive(Clone)]
struct CleanupEvidence {
    file_read: nestlink_remote::files::FileWorkerMonitor,
    file_write: nestlink_remote::upload::FileWriteMonitor,
    clipboard: nestlink_remote::clipboard::ClipboardWorkerMonitor,
    shutdown_calls: Arc<AtomicUsize>,
}

fn make_service_state(permit: &VerifiedPermit, source: Vec<u8>) -> ServiceState {
    ServiceState {
        file_read_root: nestlink_auth::random_id(),
        file_write_root: nestlink_auth::random_id(),
        source: Arc::new(source),
        read_allowed: Arc::new(AtomicBool::new(true)),
        write_allowed: Arc::new(AtomicBool::new(true)),
        clipboard_binding: ClipboardBinding {
            session_id: permit.claims().session_id.clone(),
            connection_generation: permit.claims().connection_generation,
        },
        clipboard_read_allowed: Arc::new(AtomicBool::new(true)),
        clipboard_write_allowed: Arc::new(AtomicBool::new(true)),
        clipboard_text: Arc::new(Mutex::new("host clipboard initial".into())),
        uploaded: Arc::new(Mutex::new(HashMap::new())),
        read_device_drops: Arc::new(AtomicUsize::new(0)),
        write_device_drops: Arc::new(AtomicUsize::new(0)),
        clipboard_closed: Arc::new(AtomicBool::new(false)),
    }
}

struct ManagedDataFixture {
    _server: RenewalServer,
    controller_sdk: Sdk,
    host_sdk: Sdk,
    permit: VerifiedPermit,
}

impl ManagedDataFixture {
    async fn new(controller: &DeviceIdentity, host: &DeviceIdentity) -> TestResult<Self> {
        use nestlink_auth::{Secret, VaultKey, random_id};
        use nestlink_protocol::api::{ApprovalChoice, RemoteRequest};
        use nestlink_server::{AppState, router};
        use nestlink_storage::Store;

        let deployment_id = random_id();
        let signer = nestlink_identity::PermitSigner::generate();
        let issuer = signer.public_key();
        let trust = || crate::DeploymentTrust {
            deployment_id: deployment_id.clone(),
            permit_issuer: issuer,
        };
        let password = "webrtc-proved-data-binding-regression-password";
        let mut store = Store::in_memory(&deployment_id)?;
        store.bootstrap_admin("admin", password)?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("http://{}", listener.local_addr()?);
        let app = router(AppState::new(
            store,
            VaultKey::from_bytes([64; 32]),
            signer,
            origin.clone(),
            false,
        )?);
        let server = RenewalServer(tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        }));
        let mut controller_sdk = Sdk::connect(&origin, trust(), true).await?;
        controller_sdk
            .login("admin".into(), Secret::from_text(password.into()), None)
            .await?;
        let mut host_sdk = Sdk::connect(&origin, trust(), true).await?;
        host_sdk
            .login("admin".into(), Secret::from_text(password.into()), None)
            .await?;
        controller_sdk
            .register_browser_endpoint(controller, "Data controller".into(), "direct_only".into())
            .await?;
        host_sdk
            .enroll(
                host,
                "Data host".into(),
                "windows".into(),
                vec!["host".into(), "vp8".into()],
                "direct_only".into(),
            )
            .await?;
        let permissions: Vec<_> = DATA_PERMISSIONS.iter().map(|value| *value as i32).collect();
        let request = controller_sdk
            .create_remote(RemoteRequest {
                id: random_id(),
                controller_device_id: controller.device_id.clone(),
                host_device_id: host.device_id.clone(),
                permissions: permissions.clone(),
                path_mode: "direct_only".into(),
            })
            .await?;
        host_sdk
            .approve(
                host,
                &request,
                ApprovalChoice {
                    approved: true,
                    permissions,
                    paths: vec![Path::Direct as i32],
                },
            )
            .await?;
        let prepared = host_sdk.remote(&request.id).await?;
        host_sdk.mark_browser_host_ready(host, &prepared).await?;
        let permit = controller_sdk.permit(&request.id).await?;
        assert!(permit.claims().is_setup());
        Ok(Self {
            _server: server,
            controller_sdk,
            host_sdk,
            permit,
        })
    }
}

#[tokio::test]
async fn proved_webrtc_business_channels_run_real_file_and_clipboard_rpcs_and_clean_owners()
-> TestResult {
    run_proved_data_rpcs(false).await
}

#[tokio::test]
async fn production_setup_activation_keeps_proved_data_binding_through_renewal_and_revocation()
-> TestResult {
    run_proved_data_rpcs(true).await
}

async fn run_proved_data_rpcs(activate_setup: bool) -> TestResult {
    let controller = DeviceIdentity::generate();
    let host_identity = DeviceIdentity::generate();
    let management = if activate_setup {
        Some(ManagedDataFixture::new(&controller, &host_identity).await?)
    } else {
        None
    };
    let permit = if let Some(management) = &management {
        management.permit.clone()
    } else {
        test_permit_with_permissions(&controller, &host_identity, DATA_PERMISSIONS.to_vec())?
    };
    // Match BrowserDataChannels: capture the signed channel identity before
    // offering or proving the connection, never after setup activation.
    let kinds = data::authorized_channels(&permit);
    let permit_digest = data::permit_digest(&permit)?;
    let controller_bindings: Vec<_> = kinds
        .iter()
        .copied()
        .map(|kind| WebRtcDataBinding::for_permit(permit.claims(), permit_digest, kind))
        .collect::<Result<_, _>>()?;
    let mut pair = LoopbackPair::connected(&permit, &controller, &host_identity).await?;
    let controller_clock = pair
        .controller_setup
        .as_ref()
        .ok_or_else(|| io::Error::other("controller setup missing"))?
        .clock
        .clone();
    let file_payload: Vec<_> = (0..FILE_PAYLOAD_BYTES as usize + 19)
        .map(|index| (index % 251) as u8)
        .collect();
    let state = make_service_state(&permit, file_payload.clone());
    let shutdown_calls = Arc::new(AtomicUsize::new(0));
    let evidence = Arc::new(Mutex::new(None::<CleanupEvidence>));
    let factory_state = state.clone();
    let factory_shutdown_calls = shutdown_calls.clone();
    let factory_evidence = evidence.clone();
    let factory: HostDataFactory = Box::new(move |mut claims| {
        let file_read = FileReadServer::start_claimed(
            claims
                .file_read
                .take()
                .ok_or(WebRtcHostError::BusinessDataChannel)?,
            MemoryReadDevice(factory_state.clone()),
        )?;
        let file_write = FileWriteServer::start_claimed(
            claims
                .file_write
                .take()
                .ok_or(WebRtcHostError::BusinessDataChannel)?,
            MemoryWriteDevice(factory_state.clone()),
        )?;
        let clipboard = ClipboardServer::start_claimed(
            claims
                .clipboard
                .take()
                .ok_or(WebRtcHostError::BusinessDataChannel)?,
            ClipboardDirections {
                read: true,
                write: true,
            },
            ClipboardDeviceFixture(factory_state),
        )?;
        let result = CleanupEvidence {
            file_read: file_read.monitor(),
            file_write: file_write.monitor(),
            clipboard: clipboard.monitor(),
            shutdown_calls: factory_shutdown_calls.clone(),
        };
        *factory_evidence
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(result);
        Ok(Box::new(LoopbackDataOwner {
            file_read: Some(file_read),
            file_write: Some(file_write),
            clipboard: Some(clipboard),
            shutdown_calls: factory_shutdown_calls,
        }))
    });

    let (controller_lease, mut running_permit) = if let Some(management) = &management {
        let (host_lease, controller_lease, running) = pair
            .activate_setup_data(management, &controller, &host_identity, factory)
            .await?;
        host_lease.check_media_binding(
            nestlink_transport_stream::Channel::Video,
            permit.claims().connection_generation,
        )?;
        (controller_lease, running)
    } else {
        let (host_lease, controller_lease) =
            pair.prove(&permit, &controller, &host_identity).await?;
        let runtime = data::HostDataRuntime::start(
            pair.host.peer.clone(),
            host_lease,
            permit.clone(),
            pair.host.permit_rx.clone(),
            pair.host.pending_data_channels.clone(),
            pair.host.cancel_tx.clone(),
            Some(factory),
        )
        .await?
        .ok_or_else(|| io::Error::other("data permissions did not start a runtime"))?;
        pair.host.data_runtime = Some(runtime);
        (controller_lease, permit.clone())
    };

    let channels: Vec<_> = kinds.iter().copied().map(data::transport_channel).collect();
    let (mut controller_external, ports) = ExternalChannelRuntime::new(
        controller_lease.clone(),
        permit.claims().connection_generation,
        &channels,
    )?;
    let (controller_permit_tx, controller_permit_rx) = watch::channel(running_permit.clone());
    let (controller_cancel, _) = watch::channel(false);
    pair.controller_cancel = controller_cancel.clone();
    let mut controller_workers: Vec<JoinHandle<Result<(), RemoteError>>> = Vec::new();
    for ((kind, port), binding) in kinds.iter().copied().zip(ports).zip(controller_bindings) {
        assert_eq!(*binding.permit_sha256(), permit.digest());
        assert_eq!(binding.lease_sequence(), permit.claims().lease_sequence);
        if management.is_some() {
            assert_ne!(*binding.permit_sha256(), running_permit.digest());
            assert_ne!(
                binding.lease_sequence(),
                running_permit.claims().lease_sequence
            );
        }
        let (channel, incoming) = pair
            .controller_business
            .remove(&kind)
            .ok_or_else(|| io::Error::other("controller DataChannel missing"))?;
        controller_workers.push(data::spawn_data_worker(
            pair.controller_peer.clone(),
            controller_cancel.clone(),
            controller_permit_rx.clone(),
            channel,
            incoming,
            port,
            binding,
        ));
    }

    let mut file_read = FileReadClient::from_claimed(controller_external.claim_file_read()?)?;
    let mut file_write = FileWriteClient::from_claimed(controller_external.claim_file_write()?)?;
    let clipboard_binding = ClipboardBinding {
        session_id: permit.claims().session_id.clone(),
        connection_generation: permit.claims().connection_generation,
    };
    let mut clipboard_transport = controller_external.claim_clipboard_transport(
        clipboard_binding,
        ClipboardDirections {
            read: true,
            write: true,
        },
    )?;
    let mut clipboard_read = ClipboardReadClient::attach_claimed(&mut clipboard_transport)?;
    let mut clipboard_write = ClipboardWriteClient::attach_claimed(&mut clipboard_transport)?;

    let roots = file_read.list_roots(&nestlink_auth::random_id()).await?;
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0].root_id, state.file_read_root);
    if let Some(management) = &management {
        // Keep the same SCTP streams and fragment bindings through a second
        // genuine signed renewal; subsequent file bytes must still pass.
        let claims = running_permit.claims();
        let due_at =
            claims.issued_at_unix_ms + (claims.expires_at_unix_ms - claims.issued_at_unix_ms) / 3;
        tokio::time::sleep(Duration::from_millis(
            due_at.saturating_sub(unix_ms()?).saturating_add(1),
        ))
        .await;
        assert!(
            pair.host
                .send_renewal_signature(&management.host_sdk, &host_identity)
                .await?
        );
        let bytes = tokio::time::timeout(
            Duration::from_secs(3),
            pair.controller_control_messages.recv(),
        )
        .await?
        .ok_or_else(|| io::Error::other("running data renewal signature missing"))?;
        let WebRtcControl::HostRenewalSignature {
            signature,
            lease_sequence: 3,
            ..
        } = WebRtcControl::decode_validated(&bytes, running_permit.claims())?
        else {
            return Err(io::Error::other("expected signed running data renewal").into());
        };
        let view = management
            .controller_sdk
            .remote(&permit.claims().session_id)
            .await?;
        let started = controller_clock.monotonic_ms();
        let fresh = management
            .controller_sdk
            .renew_permit(&controller, &view, &running_permit, signature)
            .await?;
        controller_lease.renew(fresh.clone(), started)?;
        controller_permit_tx.send_replace(fresh.clone());
        pair.host
            .refresh_authority(&management.host_sdk, &host_identity)
            .await?;
        assert_eq!(pair.host.current_permit().digest(), fresh.digest());
        assert!(!*pair.host.cancel_tx.borrow());
        running_permit = fresh;
        let renewed_roots = file_read.list_roots(&nestlink_auth::random_id()).await?;
        assert_eq!(renewed_roots.len(), 1);
        assert_eq!(renewed_roots[0].root_id, state.file_read_root);
    }
    let mut download = file_read
        .open(
            &nestlink_auth::random_id(),
            &state.file_read_root,
            "source.bin",
            0,
            None,
        )
        .await?;
    assert_eq!(download.manifest().sha256, digest(&file_payload));
    let first_chunk = file_read
        .next(&mut download)
        .await?
        .ok_or_else(|| io::Error::other("source ended before its first chunk"))?;
    assert_eq!(first_chunk.data.len(), FILE_PAYLOAD_BYTES as usize);
    assert_eq!(
        first_chunk.data,
        file_payload[..FILE_PAYLOAD_BYTES as usize]
    );
    state.read_allowed.store(false, Ordering::Release);
    assert!(matches!(
        file_read.next(&mut download).await,
        Err(nestlink_remote::files::FileReadError::Source(
            FileReadErrorCode::FileReadDenied
        ))
    ));
    state.read_allowed.store(true, Ordering::Release);

    let destination_roots = file_write.list_roots(&nestlink_auth::random_id()).await?;
    assert_eq!(destination_roots.len(), 1);
    let upload_bytes = b"real file-write RPC payload over SCTP";
    let upload_hash = digest(upload_bytes);
    let mut upload = file_write
        .open(
            &nestlink_auth::random_id(),
            &state.file_write_root,
            "target.bin",
            upload_bytes.len() as u64,
            upload_hash,
        )
        .await?;
    file_write
        .write_chunk(
            &mut upload,
            FileWriteChunk {
                offset: 0,
                data: upload_bytes.to_vec(),
                sha256: upload_hash.to_vec(),
            },
        )
        .await?;
    let receipt = file_write.commit(&mut upload).await?;
    assert_eq!(receipt.sha256, upload_hash);
    assert!(
        receipt
            .state
            .is_some_and(|state| state.published && state.file_closed)
    );
    assert_eq!(
        state
            .uploaded
            .lock()
            .map_err(|_| io::Error::other("upload map poisoned"))?
            .get("target.bin")
            .map(Vec::as_slice),
        Some(upload_bytes.as_slice())
    );
    state.write_allowed.store(false, Ordering::Release);
    assert!(matches!(
        file_write
            .open(
                &nestlink_auth::random_id(),
                &state.file_write_root,
                "target.bin",
                upload_bytes.len() as u64,
                upload_hash,
            )
            .await,
        Err(nestlink_remote::upload::FileWriteError::Destination(failure))
            if failure.code == FileWriteErrorCode::FileWriteDenied as i32
    ));

    clipboard_write
        .write_text(
            Zeroizing::new("controller text over real clipboard RPC".into()),
            Arc::new(AlwaysClipboardConsent),
        )
        .await?;
    let read = clipboard_read.read_text().await?;
    assert_eq!(
        read.text.as_deref().map(|text| text.as_str()),
        Some("controller text over real clipboard RPC")
    );
    state.clipboard_read_allowed.store(false, Ordering::Release);
    assert!(matches!(
        clipboard_read.read_text().await,
        Err(ClipboardRpcError::Refused {
            code: nestlink_protocol::ClipboardErrorCode::ClipboardDenied,
            effect: ClipboardWriteEffect::ClipboardWriteNotApplied,
        })
    ));
    state
        .clipboard_write_allowed
        .store(false, Ordering::Release);
    assert!(matches!(
        clipboard_write
            .write_text(
                Zeroizing::new("must not apply".into()),
                Arc::new(AlwaysClipboardConsent),
            )
            .await,
        Err(ClipboardRpcError::Refused {
            code: nestlink_protocol::ClipboardErrorCode::ClipboardDenied,
            effect: ClipboardWriteEffect::ClipboardWriteNotApplied,
        })
    ));
    assert_eq!(
        state
            .clipboard_text
            .lock()
            .map_err(|_| io::Error::other("clipboard fixture poisoned"))?
            .as_str(),
        "controller text over real clipboard RPC"
    );

    download = drop_download(file_read, download)?;
    drop(download);
    file_write.retire()?;
    clipboard_read.retire()?;
    clipboard_write.retire()?;
    drop(clipboard_transport);

    let stop_reason = if let Some(management) = &management {
        management
            .controller_sdk
            .revoke_remote(&permit.claims().session_id)
            .await?;
        assert!(
            pair.host
                .refresh_authority(&management.host_sdk, &host_identity)
                .await
                .is_err()
        );
        StopReason::Revoked
    } else {
        StopReason::ExplicitExit
    };
    // Stop controller workers before closing the host peer. This lets each
    // worker observe its cancellation signal instead of treating a transport
    // close as an unexpected worker failure during cleanup.
    controller_cancel.send_replace(true);
    controller_permit_tx.send_replace(running_permit);
    let close_report = pair.host.close_with_reason_report(stop_reason).await;
    assert!(!close_report.lease_stop_failed);
    assert!(!close_report.peer_close_failed);
    assert!(!close_report.data_worker_cleanup_failed);
    assert!(pair.host.data_runtime.is_none());
    assert_eq!(shutdown_calls.load(Ordering::Acquire), 1);
    assert_eq!(state.read_device_drops.load(Ordering::Acquire), 1);
    assert_eq!(state.write_device_drops.load(Ordering::Acquire), 1);
    assert!(state.clipboard_closed.load(Ordering::Acquire));
    let evidence = evidence
        .lock()
        .map_err(|_| io::Error::other("cleanup evidence poisoned"))?
        .clone()
        .ok_or_else(|| io::Error::other("service owner was not created"))?;
    assert!(evidence.file_read.status().finished);
    assert!(evidence.file_write.status().finished);
    assert!(
        evidence
            .file_write
            .status()
            .transfers
            .values()
            .all(|state| { state.file_closed && state.temporary_removed })
    );
    assert!(evidence.clipboard.status().finished);
    assert_eq!(evidence.shutdown_calls.load(Ordering::Acquire), 1);

    controller_lease.stop(stop_reason)?;
    pair.controller_peer.close().await?;
    for worker in controller_workers {
        tokio::time::timeout(Duration::from_secs(3), worker).await???;
    }
    controller_external.wait_stopped().await?;
    Ok(())
}

fn drop_download(
    client: FileReadClient,
    download: nestlink_remote::files::FileDownload,
) -> TestResult<nestlink_remote::files::FileDownload> {
    // The revoked source already received its terminal Failure; retire the
    // one-shot client only after that exact response has been consumed.
    client.retire()?;
    Ok(download)
}

struct RenewalServer(JoinHandle<()>);

impl Drop for RenewalServer {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[tokio::test]
async fn idle_offer_poll_renews_over_sctp_and_http_then_rejects_revocation() -> TestResult {
    use nestlink_auth::{Secret, VaultKey, random_id};
    use nestlink_protocol::api::{ApprovalChoice, RemoteRequest};
    use nestlink_server::{AppState, router};
    use nestlink_storage::Store;

    let deployment_id = random_id();
    let signer = nestlink_identity::PermitSigner::generate();
    let permit_issuer = signer.public_key();
    let trust = || crate::DeploymentTrust {
        deployment_id: deployment_id.clone(),
        permit_issuer,
    };
    let password = "webrtc-idle-renewal-regression-password";
    let mut store = Store::in_memory(&deployment_id)?;
    store.bootstrap_admin("admin", password)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    // Hold one genuine signed permit response while the controller commits
    // its renewal. The following request-view read must observe sequence 2.
    let crossing = Arc::new(AtomicBool::new(false));
    let permit_read = Arc::new(tokio::sync::Notify::new());
    let release_read = Arc::new(tokio::sync::Notify::new());
    let held_reads = Arc::new(AtomicUsize::new(0));
    let gate_armed = crossing.clone();
    let gate_observed = permit_read.clone();
    let gate_release = release_read.clone();
    let gate_count = held_reads.clone();
    let app = router(AppState::new(
        store,
        VaultKey::from_bytes([63; 32]),
        signer,
        origin.clone(),
        false,
    )?)
    .layer(axum::middleware::from_fn(
        move |request: axum::extract::Request, next: axum::middleware::Next| {
            let hold = request.method() == axum::http::Method::GET
                && request.uri().path().ends_with("/permit")
                && gate_armed.swap(false, Ordering::AcqRel);
            let observed = gate_observed.clone();
            let release = gate_release.clone();
            let count = gate_count.clone();
            async move {
                let response = next.run(request).await;
                if hold && response.status() == axum::http::StatusCode::OK {
                    count.fetch_add(1, Ordering::AcqRel);
                    observed.notify_one();
                    let _ = tokio::time::timeout(Duration::from_secs(3), release.notified()).await;
                }
                response
            }
        },
    ));
    let _server = RenewalServer(tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    }));
    let mut controller_sdk = Sdk::connect(&origin, trust(), true).await?;
    controller_sdk
        .login("admin".into(), Secret::from_text(password.into()), None)
        .await?;
    let mut host_sdk = Sdk::connect(&origin, trust(), true).await?;
    host_sdk
        .login("admin".into(), Secret::from_text(password.into()), None)
        .await?;
    let controller = DeviceIdentity::generate();
    let host_identity = DeviceIdentity::generate();
    controller_sdk
        .register_browser_endpoint(&controller, "Browser".into(), "direct_only".into())
        .await?;
    host_sdk
        .enroll(
            &host_identity,
            "Host".into(),
            "windows".into(),
            vec!["host".into(), "vp8".into()],
            "direct_only".into(),
        )
        .await?;
    let request = controller_sdk
        .create_remote(RemoteRequest {
            id: random_id(),
            controller_device_id: controller.device_id.clone(),
            host_device_id: host_identity.device_id.clone(),
            permissions: vec![Permission::View as i32, Permission::Input as i32],
            path_mode: "direct_only".into(),
        })
        .await?;
    host_sdk
        .approve(
            &host_identity,
            &request,
            ApprovalChoice {
                approved: true,
                permissions: vec![Permission::View as i32, Permission::Input as i32],
                paths: vec![Path::Direct as i32],
            },
        )
        .await?;
    let prepared = host_sdk.remote(&request.id).await?;
    host_sdk
        .mark_browser_host_ready(&host_identity, &prepared)
        .await?;
    let mut permit = controller_sdk.permit(&request.id).await?;
    let mut original_expiry = permit.claims().expires_at_unix_ms;
    assert_ne!(
        controller_sdk.remote(&request.id).await?.expires_at_unix_ms,
        original_expiry
    );
    let (setup, _startup_stop_owner) = test_setup(&permit, EndpointRole::Host)?;
    let mut startup_peer =
        WebRtcHostPeer::new(&host_sdk, &host_identity, permit.clone(), setup, |_| {
            Err(WebRtcHostError::Closed)
        })
        .await
        .map_err(|error| {
            io::Error::other(format!(
                "real management permit rejected at host startup: {error}"
            ))
        })?;
    let startup_close = startup_peer
        .close_with_reason_report(StopReason::ExplicitExit)
        .await;
    assert!(!startup_close.cleanup_failed() && !startup_close.peer_close_failed);
    let mut pair = LoopbackPair::connected(&permit, &controller, &host_identity).await?;
    let outcome = async {
        // No endpoint proof means no signature, even on an open SCTP channel.
        assert!(matches!(
            pair.host
                .send_renewal_signature(&host_sdk, &host_identity)
                .await,
            Err(WebRtcHostError::EndpointProof)
        ));
        let controller_clock = pair
            .controller_setup
            .as_ref()
            .ok_or_else(|| io::Error::other("controller setup missing"))?
            .clock
            .clone();
        let (host_lease, controller_lease) =
            pair.prove(&permit, &controller, &host_identity).await?;
        assert!(permit.claims().is_setup());
        assert!(
            host_lease
                .check_media_binding(nestlink_transport_stream::Channel::Video, 1)
                .is_err()
        );
        assert!(pair.host.input_permits_tx.borrow().is_none());
        assert!(
            pair.host
                .send_renewal_signature(&host_sdk, &host_identity)
                .await?
        );
        let bytes = tokio::time::timeout(
            Duration::from_secs(3),
            pair.controller_control_messages.recv(),
        )
        .await?
        .ok_or_else(|| io::Error::other("setup renewal signature missing"))?;
        let WebRtcControl::HostRenewalSignature {
            signature,
            lease_sequence: 2,
            ..
        } = WebRtcControl::decode_validated(&bytes, permit.claims())?
        else {
            return Err(io::Error::other("unexpected setup activation message").into());
        };
        let view = controller_sdk.remote(&request.id).await?;
        crossing.store(true, Ordering::Release);
        let (refreshed, renewal) = tokio::join!(
            pair.host
                .refresh_authority_inner(&host_sdk, &host_identity, true),
            async {
                tokio::time::timeout(Duration::from_secs(3), permit_read.notified()).await?;
                let started = controller_clock.monotonic_ms();
                let result = controller_sdk
                    .renew_permit(&controller, &view, &permit, signature)
                    .await;
                release_read.notify_one();
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>((result?, started))
            }
        );
        let (running, started) = renewal?;
        refreshed?;
        assert_eq!(held_reads.load(Ordering::Acquire), 1);
        assert_eq!(pair.host.current_permit().digest(), running.digest());
        assert!(!running.claims().is_setup());
        assert_eq!(
            running.claims().expires_at_unix_ms - running.claims().issued_at_unix_ms,
            15_000
        );
        controller_lease.renew(running.clone(), started)?;
        host_lease.check_media_binding(nestlink_transport_stream::Channel::Video, 1)?;
        permit = running;
        original_expiry = permit.claims().expires_at_unix_ms;
        let records = Arc::new(std::sync::Mutex::new(Vec::new()));
        let epoch = InputEpoch {
            input: 1,
            layout: 1,
            connection: 1,
        };
        let layout = InputLayout {
            left: -1920,
            top: 0,
            width: 1920,
            height: 1080,
        };
        let input = InputController::attach(
            host_lease.clone(),
            RecordingInputDevice(records.clone()),
            epoch,
            layout,
        )?;
        let mut received_input = pair
            .host
            .input_messages
            .take()
            .ok_or_else(|| io::Error::other("renewal input queue missing"))?;
        let (worker_tx, worker_rx) = mpsc::channel(MAX_PENDING_INPUT_MESSAGES);
        let (arrived_tx, mut arrived_rx) = mpsc::channel(8);
        // Observe actual SCTP delivery, forwarding precisely the original bytes
        // into the production worker. The observer never creates input frames.
        let _input_delivery = RenewalServer(tokio::spawn(async move {
            while let Some(bytes) = received_input.recv().await {
                if worker_tx.send(bytes).await.is_err() || arrived_tx.send(()).await.is_err() {
                    return;
                }
            }
        }));
        pair.host.input_worker = Some(spawn_input_control(
            pair.host.peer.clone(),
            pair.host.cancel_tx.clone(),
            host_lease.clone(),
            HostInputSource::new(input, epoch, layout),
            worker_rx,
            pair.host.input_permits_tx.subscribe(),
            pair.host.clock.clone(),
        ));
        let input_frame = |permit: &VerifiedPermit, sequence: u64| WebRtcControl::InputEvent {
            schema_version: SCHEMA_VERSION,
            session_id: permit.claims().session_id.clone(),
            connection_generation: permit.claims().connection_generation,
            lease_sequence: permit.claims().lease_sequence,
            input_epoch: 1,
            layout_epoch: 1,
            sequence,
            action: WebRtcInputAction::Pointer {
                button: Some(1),
                down: !sequence.is_multiple_of(2),
                x: -960,
                y: 540,
            },
        };
        let actions = |items: &[RecordedInput]| {
            items
                .iter()
                .filter(|item| matches!(item, RecordedInput::Action(_)))
                .count()
        };
        assert!(!pair.host.renewal_due()?);
        assert!(
            !pair
                .host
                .answer_next_offer(&host_sdk, &host_identity)
                .await?
        );
        assert!(pair.controller_control_messages.try_recv().is_err());

        for next_sequence in 3..=4 {
            let claims = permit.claims();
            let due_at = claims.issued_at_unix_ms
                + (claims.expires_at_unix_ms - claims.issued_at_unix_ms) / 3;
            tokio::time::sleep(Duration::from_millis(due_at.saturating_sub(unix_ms()?))).await;
            assert!(pair.host.renewal_due()?);
            // This is the same production poll used by AppCore. No new offer
            // is published during either renewal round.
            assert!(
                !pair
                    .host
                    .answer_next_offer(&host_sdk, &host_identity)
                    .await?
            );
            let bytes = tokio::time::timeout(
                Duration::from_secs(1),
                pair.controller_control_messages.recv(),
            )
            .await?
            .ok_or_else(|| io::Error::other("host renewal channel closed"))?;
            let WebRtcControl::HostRenewalSignature {
                lease_sequence,
                signature,
                ..
            } = WebRtcControl::decode_validated(&bytes, permit.claims())?
            else {
                return Err(io::Error::other("expected host renewal signature").into());
            };
            assert_eq!(lease_sequence, next_sequence);
            assert_eq!(pair.host.current_permit().digest(), permit.digest());
            assert_eq!(
                host_sdk
                    .host_permit(&host_identity, &request.id)
                    .await?
                    .digest(),
                permit.digest()
            );
            assert!(!pair.host.renewal_due()?);
            assert!(
                !pair
                    .host
                    .answer_next_offer(&host_sdk, &host_identity)
                    .await?
            );
            assert!(
                !pair
                    .host
                    .send_renewal_signature(&host_sdk, &host_identity)
                    .await?
            );
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(100),
                    pair.controller_control_messages.recv(),
                )
                .await
                .is_err()
            );

            let view = controller_sdk.remote(&request.id).await?;
            let request_started_ms = controller_clock.monotonic_ms();
            let fresh = controller_sdk
                .renew_permit(&controller, &view, &permit, signature.clone())
                .await?;
            controller_lease.renew(fresh.clone(), request_started_ms)?;
            assert!(
                controller_sdk
                    .renew_permit(&controller, &view, &permit, signature)
                    .await
                    .is_err()
            );
            if next_sequence == 3 {
                // Browser authority has advanced, while host still has lease 1.
                send_browser_control(&pair.controller_control, &fresh, input_frame(&fresh, 1))
                    .await?;
                tokio::time::timeout(Duration::from_secs(1), arrived_rx.recv())
                    .await?
                    .ok_or_else(|| io::Error::other("new-lease input was not delivered by SCTP"))?;
                assert_eq!(pair.host.current_permit().digest(), permit.digest());
                assert!(
                    tokio::time::timeout(
                        Duration::from_millis(75),
                        wait_for_input_records(&records, |items| actions(items) > 0),
                    )
                    .await
                    .is_err()
                );
                assert!(host_lease.subscribe_stopped().borrow().is_none());
            }
            // Let the production authority refresh interval elapse.
            tokio::time::sleep(SIGNAL_REFRESH_INTERVAL + Duration::from_millis(20)).await;
            assert!(
                !pair
                    .host
                    .answer_next_offer(&host_sdk, &host_identity)
                    .await?
            );
            assert_eq!(pair.host.current_permit().digest(), fresh.digest());
            if next_sequence == 3 {
                wait_for_input_records(&records, |items| actions(items) == 1).await?;
            } else {
                // Reverse race: host is now on lease 3, but an old lease-2 frame
                // arrives before the first lease-3 input. It keeps its original
                // deadline and the same global input sequence.
                send_browser_control(&pair.controller_control, &permit, input_frame(&permit, 2))
                    .await?;
                tokio::time::timeout(Duration::from_secs(1), arrived_rx.recv())
                    .await?
                    .ok_or_else(|| io::Error::other("old-lease input was not delivered by SCTP"))?;
                wait_for_input_records(&records, |items| actions(items) == 2).await?;
                send_browser_control(&pair.controller_control, &fresh, input_frame(&fresh, 3))
                    .await?;
                tokio::time::timeout(Duration::from_secs(1), arrived_rx.recv())
                    .await?
                    .ok_or_else(|| {
                        io::Error::other("current-lease input was not delivered by SCTP")
                    })?;
                wait_for_input_records(&records, |items| actions(items) == 3).await?;
            }
            host_lease.check_media_binding(nestlink_transport_stream::Channel::Video, 1)?;
            assert!(host_lease.subscribe_stopped().borrow().is_none());
            permit = fresh;
        }
        // Earlier renewals keep the session alive before the original lease
        // expires. Wait for that original deadline explicitly so this test
        // still proves the refreshed session survives beyond lease 1.
        let until_original_expiry = original_expiry.saturating_sub(unix_ms()?).saturating_add(1);
        tokio::time::sleep(Duration::from_millis(until_original_expiry)).await;
        assert!(unix_ms()? > original_expiry);
        controller_sdk.revoke_remote(&request.id).await?;
        tokio::time::sleep(SIGNAL_REFRESH_INTERVAL + Duration::from_millis(20)).await;
        assert!(
            pair.host
                .answer_next_offer(&host_sdk, &host_identity)
                .await
                .is_err()
        );
        assert!(pair.controller_control_messages.try_recv().is_err());
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    }
    .await;
    // Keep failures reviewable without leaving peers or lease owners behind.
    let close = pair
        .host
        .close_with_reason_report(StopReason::ExplicitExit)
        .await;
    let controller_close = pair.controller_peer.close().await;
    outcome?;
    controller_close?;
    assert!(!close.cleanup_failed() && !close.peer_close_failed);
    Ok(())
}
