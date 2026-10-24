#![cfg(windows)]

// Reuse the real management service, trust proof and sign-in fixture.
#[path = "../../app-core/tests/support/mod.rs"]
mod support;

use nestlink_app_core::{
    Action, AppCore, CoreHandle, Limits, NativeSessionBinding, NativeSessionConfig,
    NativeVideoBinding, RemoteAccess, ShutdownState, VideoSinkContext,
};
use nestlink_app_ipc::{
    compressed_video::{ClientControl, CompressedVideoClient, NativeCompressedOpen, ServerControl},
    serve,
};
use nestlink_local_ipc::LocalServer;
use nestlink_media_codec::{EncodedVideo, MfH264Decoder, MfH264Encoder, VideoCodec, VideoConfig};
use nestlink_protocol::{
    Path, Permission, api::ApprovalChoice, media::H264_CAPABILITY,
    native_displays::DisplayDescriptor,
};
use nestlink_sdk::{DeviceIdentity, NetworkMonitor};
use std::{
    io,
    net::UdpSocket,
    sync::{Arc, mpsc},
    thread,
    time::{Duration, Instant},
};
use support::{Result, Server, connect, success};
use tokio::{sync::oneshot, task::JoinSet};

const WIDTH: u32 = 64;
const HEIGHT: u32 = 48;
const FRAME_COUNT: usize = 12;
const STAGE_LIMIT: Duration = Duration::from_secs(20);

async fn bounded<T>(
    stage: &'static str,
    action: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    tokio::time::timeout(STAGE_LIMIT, action)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, stage))?
}

async fn join_finished<T: Send + 'static>(
    worker: thread::JoinHandle<T>,
    stage: &'static str,
) -> Result<T> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !worker.is_finished() {
        if tokio::time::Instant::now() >= deadline {
            // Dropping a std handle detaches the stalled native owner. No
            // Tokio blocking task can keep runtime shutdown waiting forever,
            // and no caller receives a successful ownership-join receipt.
            return Err(io::Error::new(io::ErrorKind::TimedOut, stage).into());
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    worker.join().map_err(|_| io::Error::other(stage).into())
}

fn initial_codec_unavailable(error: &io::Error) -> bool {
    // Only an absent MF codec/class may skip before the first frame. Geometry,
    // negotiation, output and cleanup errors remain failures.
    error.kind() == io::ErrorKind::Unsupported
        || ["0xc00d5212", "0x80040154"]
            .iter()
            .any(|code| error.to_string().contains(code))
}

fn synthetic_packets() -> Result<Option<Vec<EncodedVideo>>> {
    let mut encoder = match MfH264Encoder::new(
        VideoConfig {
            width: WIDTH,
            height: HEIGHT,
            fps: 30,
            bitrate_kbps: 256,
        },
        false,
    ) {
        Ok(encoder) => encoder,
        Err(error) if initial_codec_unavailable(&error) => {
            eprintln!("SKIP compressed_ipc initial_software_encoder_unavailable: {error}");
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    assert!(
        !encoder.hardware(),
        "this case requires the software encoder"
    );
    let pixels = [32, 160, 64, 255].repeat((WIDTH * HEIGHT) as usize);
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut packets = Vec::new();
    let mut input = 0u64;
    while packets.len() < FRAME_COUNT {
        if Instant::now() >= deadline || input >= 64 {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "software encoder output").into());
        }
        let step = encoder.encode_step(&pixels, input * 3000, input == 0)?;
        if step.accepted {
            input += 1;
        }
        if let Some(packet) = step.output {
            packets.push(packet);
        }
    }
    assert!(packets[0].keyframe, "the real chain must begin with an IDR");
    encoder.close()?;
    Ok(Some(packets))
}

struct DecodeRequest {
    bytes: Vec<u8>,
    pts: u64,
    reply: oneshot::Sender<io::Result<u64>>,
}
struct DecoderOwner {
    requests: Option<mpsc::SyncSender<DecodeRequest>>,
    thread: Option<thread::JoinHandle<()>>,
}
impl DecoderOwner {
    async fn start() -> Result<Option<Self>> {
        let (requests, receive) = mpsc::sync_channel::<DecodeRequest>(1);
        let (ready, started) = oneshot::channel();
        let worker = thread::spawn(move || {
            let mut decoder = match MfH264Decoder::new(WIDTH, HEIGHT, false) {
                Ok(decoder) => decoder,
                Err(error) => {
                    let _ = ready.send(Err(error));
                    return;
                }
            };
            assert!(
                !decoder.hardware(),
                "this case requires the software decoder"
            );
            if ready.send(Ok(())).is_err() {
                return;
            }
            while let Ok(request) = receive.recv() {
                let decoded = (|| -> io::Result<u64> {
                    let deadline = Instant::now() + Duration::from_secs(2);
                    let mut output = decoder.decode_frame(&request.bytes, request.pts)?;
                    while output.is_none() {
                        if Instant::now() >= deadline {
                            return Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "actual software decode output",
                            ));
                        }
                        output = decoder.drain_frame()?;
                        thread::sleep(Duration::from_millis(1));
                    }
                    let (pixels, pts) =
                        output.ok_or_else(|| io::Error::other("missing decode output"))?;
                    if pixels.len() != (WIDTH * HEIGHT * 4) as usize
                        || !pixels
                            .chunks_exact(4)
                            .step_by(37)
                            .all(|pixel| (i32::from(pixel[1]) - 160).abs() < 20)
                    {
                        return Err(io::Error::other("synthetic decoded pixels differ"));
                    }
                    Ok(pts)
                })();
                let _ = request.reply.send(decoded);
            }
            // Destroy the decoder on its COM owner thread before join succeeds.
            drop(decoder);
        });
        let mut owner = Self {
            requests: Some(requests),
            thread: Some(worker),
        };
        match tokio::time::timeout(Duration::from_secs(5), started).await?? {
            Ok(()) => Ok(Some(owner)),
            Err(error) if initial_codec_unavailable(&error) => {
                eprintln!("SKIP compressed_ipc initial_software_decoder_unavailable: {error}");
                owner.join().await?;
                Ok(None)
            }
            Err(error) => Err(error.into()),
        }
    }
    async fn decode(&self, bytes: Vec<u8>, pts: u64) -> Result<u64> {
        let (reply, decoded) = oneshot::channel();
        self.requests
            .as_ref()
            .ok_or("decoder owner closed")?
            .try_send(DecodeRequest { bytes, pts, reply })?;
        Ok(tokio::time::timeout(Duration::from_secs(3), decoded).await???)
    }
    async fn join(&mut self) -> Result {
        self.requests.take();
        if let Some(worker) = self.thread.take() {
            join_finished(worker, "decoder owner did not join cleanly").await?;
        }
        Ok(())
    }
}
impl Drop for DecoderOwner {
    fn drop(&mut self) {
        self.requests.take();
    }
}

type NativePair = (
    AppCore,
    AppCore,
    CoreHandle,
    CoreHandle,
    NativeSessionBinding,
);

async fn native_pair(server: &Server) -> Result<NativePair> {
    let route = UdpSocket::bind("0.0.0.0:0")?;
    route.connect("192.0.2.1:9")?; // Route lookup only; no external packet.
    let ip = route.local_addr()?.ip();
    if !ip.is_ipv4() || ip.is_loopback() {
        return Err("no routed IPv4 test interface".into());
    }
    let identity = DeviceIdentity::generate();
    let host_id = identity.device_id.clone();
    let config = || -> Result<NativeSessionConfig> {
        let mut config = NativeSessionConfig::new(Arc::new(NetworkMonitor::start()?));
        config.use_deployment_stun = false;
        config.private_network_prefixes = vec![format!("{ip}/32")];
        // Software availability was actually probed before this capability.
        config.supported_capabilities = vec!["vp8".into(), H264_CAPABILITY.into(), "opus".into()];
        Ok(config)
    };
    let controller = AppCore::with_identity_and_native_session(
        Limits::default(),
        DeviceIdentity::generate(),
        config()?,
    )?;
    let host = AppCore::with_identity_and_native_session(Limits::default(), identity, config()?)?;
    let controller_handle = connect(&controller, server).await?;
    let host_handle = connect(&host, server).await?;
    for (handle, role) in [(&controller_handle, "controller"), (&host_handle, "host")] {
        success(handle.submit(Action::EnrollLocalDevice {
            name: role.into(),
            platform: "windows".into(),
            capabilities: vec![
                role.into(),
                "vp8".into(),
                H264_CAPABILITY.into(),
                "opus".into(),
            ],
            path_mode: "direct_only".into(),
        })?)
        .await?;
    }
    let permissions = vec![Permission::View as i32];
    success(controller_handle.submit(Action::RequestRemote {
        host_device_id: host_id,
        permissions: permissions.clone(),
        path_mode: "direct_only".into(),
        access: RemoteAccess::LocalApproval,
    })?)
    .await?;
    let request = controller_handle
        .snapshot()
        .selected_request
        .data
        .as_ref()
        .ok_or("remote request missing")?
        .clone();
    success(host_handle.submit(Action::ApproveRemote {
        request_id: request.id.clone(),
        expected_nonce: request.nonce.clone(),
        expected_policy_revision: request.policy_revision,
        choice: ApprovalChoice {
            approved: true,
            permissions,
            paths: vec![Path::Direct as i32],
        },
    })?)
    .await?;
    success(controller_handle.submit(Action::IssueRemotePermit {
        request_id: request.id.clone(),
    })?)
    .await?;
    let controller_start = controller_handle.submit(Action::StartNativeSession {
        request_id: request.id.clone(),
    })?;
    let host_start = host_handle.submit(Action::StartNativeSession {
        request_id: request.id.clone(),
    })?;
    tokio::try_join!(success(controller_start), success(host_start))?;
    let binding = host_handle
        .native_host_session_binding()
        .ok_or("proved host binding missing")?;
    assert_eq!(
        host_handle.native_video_codec(&binding)?,
        VideoCodec::H264Baseline
    );
    Ok((controller, host, controller_handle, host_handle, binding))
}

async fn select_synthetic_display(
    host: &CoreHandle,
    controller: &CoreHandle,
    binding: &NativeSessionBinding,
) -> Result {
    host.publish_native_display_candidates(
        binding,
        vec![DisplayDescriptor {
            source: 0,
            left: 0,
            top: 0,
            width: WIDTH,
            height: HEIGHT,
            label: "Synthetic IPC test".into(),
        }],
        true,
    )?;
    host.configure_native_video_stream(binding, 0, WIDTH, HEIGHT, 1)
        .await?;
    host.advertise_native_displays(binding).await?;
    let request = loop {
        if let Some(request) = host.native_display_switch_request(binding)? {
            break request;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    let selected = host.commit_native_display_switch(binding, &request).await?;
    loop {
        let view = controller.native_displays(binding)?;
        if view.catalog_acknowledged
            && view.pending.is_none()
            && view.selected.as_ref() == Some(&selected)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    Ok(())
}

struct IpcOwner {
    server: Arc<LocalServer>,
    task: tokio::task::JoinHandle<()>,
}
impl IpcOwner {
    async fn start(root: &std::path::Path, core: CoreHandle) -> Result<Self> {
        let server = Arc::new(LocalServer::bind(root).await?);
        let listener = server.clone();
        let task = tokio::spawn(async move {
            let (exit, _requests) = tokio::sync::mpsc::channel(1);
            let mut connections = JoinSet::new();
            while let Ok(pending) = listener.accept().await {
                let core = core.clone();
                let exit = exit.clone();
                connections
                    .spawn(async move { serve(pending.authenticate().await?, core, exit).await });
            }
        });
        Ok(Self { server, task })
    }
}
impl Drop for IpcOwner {
    fn drop(&mut self) {
        self.server.stop();
        self.task.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_tls_connections_reuse_decoded_credit_and_release_only_after_owner_join() -> Result {
    let packets = bounded("software encoder creation and actual output", async {
        let (reply, result) = oneshot::channel();
        let worker = thread::spawn(move || {
            let _ = reply.send(synthetic_packets());
        });
        let packets = result.await??;
        join_finished(worker, "encoder owner did not join cleanly").await?;
        Ok(packets)
    })
    .await?;
    let Some(packets) = packets else {
        return Ok(());
    };
    let Some(mut decoder) = DecoderOwner::start().await? else {
        return Ok(());
    };
    let service = bounded("real management service", Server::start(None)).await?;
    let (mut controller, mut host, controller_handle, host_handle, binding) =
        bounded("proved H264 native pair", native_pair(&service)).await?;
    bounded(
        "synthetic display SelectionAck",
        select_synthetic_display(&host_handle, &controller_handle, &binding),
    )
    .await?;
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("compressed");
    let _ipc = bounded(
        "local TLS listener",
        IpcOwner::start(&root, controller_handle.clone()),
    )
    .await?;
    let opened = bounded("control and data TLS open", async {
        Ok(CompressedVideoClient::open(
            &root,
            NativeCompressedOpen {
                ui_generation: controller_handle.snapshot().generation,
                request_id: binding.request_id.clone(),
                connection_generation: binding.connection_generation,
                source: 0,
            },
        )
        .await?)
    })
    .await?;
    let context = opened.context.clone();
    let (mut feedback, mut controls, mut data, owner) = opened.split();
    bounded("Prepare and Activate", async {
        loop {
            match controls.receive().await? {
                ServerControl::Prepare {
                    context: received,
                    width,
                    height,
                    ..
                } => {
                    assert_eq!(received, context);
                    assert_eq!((width, height), (WIDTH, HEIGHT));
                    feedback
                        .send(ClientControl::Prepared {
                            context: context.clone(),
                        })
                        .await?;
                }
                ServerControl::Authority {
                    context: received, ..
                } => assert_eq!(received, context),
                ServerControl::Activate { context: received } => {
                    assert_eq!(received, context);
                    break;
                }
                ServerControl::Stop { .. } => return Err("stopped before activation".into()),
            }
        }
        Ok(())
    })
    .await?;

    for (index, packet) in packets.into_iter().enumerate() {
        bounded("real AU delivery and decoded credit", async {
            let pts = host_handle.native_video_capture_pts(&binding, Instant::now())?;
            host_handle
                .send_native_video_frame(
                    &binding,
                    NativeVideoBinding {
                        source: 0,
                        width: WIDTH,
                        height: HEIGHT,
                        layout_epoch: context.layout_epoch,
                    },
                    pts,
                    packet.keyframe,
                    packet.data,
                )
                .await?;
            let unit = data.receive().await?;
            assert_eq!(
                unit.context, context,
                "credit reuse must not reset the decode epoch"
            );
            assert_eq!(unit.delivery_sequence, index as u64 + 1);
            assert_eq!(unit.native_sequence, index as u64 + 1);
            assert_eq!(unit.pts_90khz, pts);
            feedback
                .send(ClientControl::Accepted {
                    context: context.clone(),
                    delivery_sequence: unit.delivery_sequence,
                })
                .await?;
            let actual_pts = decoder
                .decode(unit.payload.to_vec(), unit.pts_90khz)
                .await?;
            assert_eq!(
                actual_pts, unit.pts_90khz,
                "receipt must name actual decoder output"
            );
            feedback
                .send(ClientControl::Decoded {
                    context: context.clone(),
                    delivery_sequence: unit.delivery_sequence,
                    native_sequence: unit.native_sequence,
                    pts_90khz: actual_pts,
                })
                .await?;
            // Read control messages each frame; any unexpected reprepare/stop is
            // a failure, not a silently accepted recovery of the credit test.
            match controls.receive().await? {
                ServerControl::Authority {
                    context: received, ..
                } => assert_eq!(received, context),
                _ => return Err("unexpected control transition during credit reuse".into()),
            }
            Ok(())
        })
        .await?;
    }
    bounded("Fence, actual decoder join, and cleanup receipt", async {
        feedback
            .send(ClientControl::Fence {
                context: context.clone(),
            })
            .await?;
        loop {
            match controls.receive().await? {
                ServerControl::Stop { context: received } => {
                    assert_eq!(received, context);
                    break;
                }
                ServerControl::Authority { .. } => {}
                _ => return Err("unexpected transition while fencing".into()),
            }
        }
        assert!(
            controller_handle
                .native_compressed_context(&binding)?
                .is_some(),
            "Fence cannot fabricate joined ownership"
        );
        decoder.join().await?;
        feedback
            .send(ClientControl::Stopped {
                context: context.clone(),
                joined: true,
            })
            .await?;
        while controller_handle
            .native_compressed_context(&binding)?
            .is_some()
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let retired = VideoSinkContext {
            catalog_sha256: context.catalog_sha256,
            format_epoch: context.format_epoch,
            format_sha256: context.format_sha256,
            format: context.video_format()?,
            connection_generation: context.binding.connection_generation,
            source: context.binding.source,
            stream_id: context.binding.stream_id,
            stream_epoch: context.binding.stream_epoch,
            catalog_revision: context.catalog_revision,
            selection_sequence: context.selection_sequence,
            layout_epoch: context.layout_epoch,
            decode_epoch: context.decode_epoch,
            configuration_id: context.configuration_id,
        };
        assert!(
            controller_handle
                .poll_native_compressed(&binding, &retired)
                .is_err()
        );
        assert!(
            controller_handle
                .native_compressed_feedback(
                    &binding,
                    &retired,
                    nestlink_app_core::VideoSinkFeedback::Prepared
                )
                .is_err()
        );
        Ok(())
    })
    .await?;
    drop(owner);
    bounded("normal native stop after external cleanup", async {
        success(controller_handle.submit(Action::StopNativeSession {
            request_id: binding.request_id.clone(),
            connection_generation: binding.connection_generation,
        })?)
        .await?;
        Ok(())
    })
    .await?;
    assert_eq!(
        controller.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    assert_eq!(
        host.shutdown(Duration::from_secs(5)).await,
        ShutdownState::Complete
    );
    eprintln!(
        "compressed_ipc actual_two_tls=true software_decoded=12 credit_reused=true owner_joined_before_receipt=true"
    );
    Ok(())
}
