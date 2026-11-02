//! Hosted kernel tc experiment. Synthetic moving capture and input observation
//! isolate original transport/media/file scheduling; no OS display claim.
use super::*;
use nestlink_identity::digest;
use nestlink_protocol::FileReadManifest;
use nestlink_remote::{
    files::{
        FileReadClient, FileReadConsent, FileReadDevice, FileReadServer, FileReadSource,
        FileReadVerifier,
    },
    input::{InputAction, InputController, InputDevice, InputEpoch, InputEvent, PlatformInput},
};
use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    path::PathBuf,
};

const WIDTH: u32 = 640;
const HEIGHT: u32 = 360;
const ROOT: &str = "a1000000-1111-4111-8111-111111111111";
fn unix_ns() -> io::Result<u128> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_nanos())
}
struct MovingCapture(u32);
impl CaptureDevice for MovingCapture {
    fn check(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn poll_frame(&mut self) -> io::Result<Option<RawFrame>> {
        let mut pixels = vec![0; (WIDTH * HEIGHT * 4) as usize];
        for pixel in pixels.chunks_exact_mut(4) {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 17;
            self.0 ^= self.0 << 5;
            pixel.copy_from_slice(&[self.0 as u8, (self.0 >> 8) as u8, (self.0 >> 16) as u8, 255]);
        }
        Ok(Some(RawFrame {
            source: 42,
            width: WIDTH,
            height: HEIGHT,
            captured_at: Instant::now(),
            pixels,
        }))
    }
    fn reset(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[derive(Default)]
struct Samples {
    pending: std::collections::BTreeMap<u64, Instant>,
    delivered: Vec<(u64, u64)>,
}
struct ObserveInput(Arc<Mutex<Samples>>);
impl InputDevice for ObserveInput {
    fn inject(&mut self, input: PlatformInput<'_>) -> io::Result<()> {
        if let PlatformInput::Action(InputAction::Text(text)) = input {
            let sequence: u64 = text.parse().map_err(io::Error::other)?;
            let mut samples = self
                .0
                .lock()
                .map_err(|_| io::Error::other("samples poisoned"))?;
            let started = samples
                .pending
                .remove(&sequence)
                .ok_or_else(|| io::Error::other("unknown input sample"))?;
            samples.delivered.push((
                sequence,
                started
                    .elapsed()
                    .as_micros()
                    .try_into()
                    .map_err(io::Error::other)?,
            ));
        }
        Ok(())
    }
}
struct DiskDevice(PathBuf);
struct DiskSource {
    file: File,
    consent: Arc<AtomicBool>,
}
impl FileReadDevice for DiskDevice {
    fn open(&mut self, root: &str, path: &str) -> io::Result<Box<dyn FileReadSource>> {
        if root != ROOT || path != "payload.bin" {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(Box::new(DiskSource {
            file: File::open(&self.0)?,
            consent: Arc::new(AtomicBool::new(true)),
        }))
    }
}
impl FileReadSource for DiskSource {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        self.consent.clone()
    }
    fn describe(
        &mut self,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<FileReadManifest> {
        authorized()?;
        let size = self.file.metadata()?.len();
        if size > 4 * 1024 * 1024 {
            return Err(io::Error::other("fixture size changed"));
        }
        self.file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        self.file.by_ref().take(size + 1).read_to_end(&mut bytes)?;
        authorized()?;
        if bytes.len() as u64 != size {
            return Err(io::Error::other("fixture changed"));
        }
        Ok(FileReadManifest {
            size,
            sha256: digest(&bytes).to_vec(),
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
        let remaining = self
            .file
            .metadata()?
            .len()
            .checked_sub(offset)
            .ok_or_else(|| io::Error::other("invalid offset"))?;
        let mut bytes = vec![0; remaining.min(maximum.min(65_536) as u64) as usize];
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.read_exact(&mut bytes)?;
        authorized()?;
        Ok(bytes)
    }
    fn verify(
        &mut self,
        original: &FileReadManifest,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        if self.describe(authorized)? != *original {
            return Err(io::Error::other("file changed during read"));
        }
        Ok(())
    }
}
async fn marker(root: &std::path::Path, name: &str) -> Result {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !root.join(name).exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    Ok(())
}
async fn phase(
    duration: Duration,
    sender: &nestlink_remote::ChannelSender,
    samples: &Mutex<Samples>,
    receiver: &mut VideoReceiver,
    sequence: &mut u64,
) -> Result<usize> {
    let end = Instant::now() + duration;
    let mut presented = 0;
    while Instant::now() < end {
        *sequence += 1;
        samples
            .lock()
            .map_err(|_| "samples poisoned")?
            .pending
            .insert(*sequence, Instant::now());
        let event = InputEvent {
            epoch: InputEpoch {
                input: 1,
                layout: EPOCH.layout,
                connection: EPOCH.connection,
            },
            sequence: *sequence,
            action: InputAction::Text(sequence.to_string()),
        };
        sender.send(Channel::Input, &event.encode()?).await?;
        if receiver.poll_video()?.is_some() {
            presented += 1;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Ok(presented)
}
fn percentile(samples: &Samples, first: u64, last: u64) -> Result<u64> {
    let mut values = samples
        .delivered
        .iter()
        .filter(|(sequence, _)| *sequence > first && *sequence <= last)
        .map(|(_, elapsed)| *elapsed)
        .collect::<Vec<_>>();
    assert!(
        values.len() >= 100,
        "at least 100 actual delivered input samples required"
    );
    values.sort_unstable();
    Ok(values[(values.len() * 95).div_ceil(100) - 1])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_tc_step_original_vp8_files_and_input() -> Result {
    assert_eq!(std::env::var("RUNNER_ENVIRONMENT")?, "github-hosted");
    let root = PathBuf::from(
        std::env::var_os("NESTLINK_MEDIA_IMPAIRMENT_DIR").ok_or("hosted driver required")?,
    );
    let mut pair = pair_for_network_lab(true, None, false, true, true).await?;
    let (signer, mut claims) = pair
        .lab_authority
        .take()
        .ok_or("explicit fixture authority required")?;
    let absolute_expiry = claims.issued_at_unix_ms + 60_000;
    let host_lease = pair.host.lease_control();
    let controller_lease = pair.controller.lease_control();
    let (renewal_stop, mut renewal_stopped) = tokio::sync::oneshot::channel();
    let renewal = tokio::spawn(async move {
        let mut renewals = 0u64;
        loop {
            tokio::select! {
                _ = &mut renewal_stopped => break,
                _ = tokio::time::sleep(Duration::from_secs(5)) => {}
            }
            let now = host_lease.renewal_clock()?;
            if now.unix_ms >= absolute_expiry {
                return Err("finite fixture authority exhausted".into());
            }
            claims.lease_sequence += 1;
            claims.issued_at_unix_ms = now.unix_ms;
            claims.expires_at_unix_ms = (now.unix_ms + 15_000).min(absolute_expiry);
            let signed = signer.sign(&claims)?.encode_to_vec();
            host_lease.renew(
                verify_permit(&signed, &signer.public_key())?,
                now.monotonic_ms,
            )?;
            controller_lease.renew(
                verify_permit(&signed, &signer.public_key())?,
                now.monotonic_ms,
            )?;
            renewals += 1;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(renewals)
    });
    let addresses = pair.quic_addresses.ok_or("real QUIC pair required")?;
    fs::write(
        root.join("ready.json"),
        format!(
            "{{\"host_port\":{},\"controller_port\":{}}}\n",
            addresses[0].port(),
            addresses[1].port()
        ),
    )?;
    marker(&root, "configured").await?;
    let layout = InputLayout {
        left: 0,
        top: 0,
        width: WIDTH,
        height: HEIGHT,
    };
    let samples = Arc::new(Mutex::new(Samples::default()));
    let input = InputController::attach(
        pair.host.lease_control(),
        ObserveInput(samples.clone()),
        InputEpoch {
            input: 1,
            layout: EPOCH.layout,
            connection: EPOCH.connection,
        },
        layout,
    )?;
    let mut input_channel = pair.host.claim_channel(Channel::Input)?;
    let input_task = tokio::spawn(async move {
        while let Ok(frame) = input_channel.receive().await {
            input.apply_frame(&frame)?;
        }
        Ok::<_, nestlink_remote::RemoteError>(())
    });
    let file_path = root.join("payload.bin");
    let mut bytes = vec![0; 4 * 1024 * 1024];
    let mut seed = 37u32;
    for byte in &mut bytes {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        *byte = seed as u8;
    }
    fs::write(&file_path, &bytes)?;
    let expected = digest(&bytes);
    drop(bytes);
    let mut file_server =
        FileReadServer::start(&mut pair.host, EPOCH.connection, DiskDevice(file_path))?;
    let mut file_client = FileReadClient::attach(&mut pair.controller, EPOCH.connection)?;
    let input_sender = pair.controller.sender();
    let stream = VideoStream {
        source: 42,
        codec: VideoConfig {
            width: WIDTH,
            height: HEIGHT,
            fps: 30,
            bitrate_kbps: 8000,
        },
    };
    let mut video = VideoSender::attach(
        &mut pair.host,
        MovingCapture(41),
        EPOCH,
        vec![Display {
            source: 42,
            logical: layout,
        }],
        vec![stream],
    )?;
    let mut receiver = VideoReceiver::attach(pair.controller, EPOCH, vec![stream])?;
    receiver.wait_ready().await?;
    let mut sequence = 0;
    let initial_frames = phase(
        Duration::from_secs(4),
        &input_sender,
        &samples,
        &mut receiver,
        &mut sequence,
    )
    .await?;
    let baseline_end = sequence;
    let baseline_stats = video.stats();
    eprintln!("actual baseline producer: {baseline_stats:?}");
    assert!(
        initial_frames > 20,
        "baseline actual decode/presentation did not progress"
    );
    let file_stop = Arc::new(AtomicBool::new(false));
    let stopped = file_stop.clone();
    let files = tokio::spawn(async move {
        let mut verified = 0u64;
        let mut bytes = 0u64;
        while !stopped.load(Ordering::Acquire) {
            let mut download = file_client
                .open(&random_id(), ROOT, "payload.bin", 0, Some(expected))
                .await?;
            let mut verifier = FileReadVerifier::new(download.manifest().clone())?;
            while let Some(chunk) = file_client.next(&mut download).await? {
                bytes += chunk.data.len() as u64;
                verifier.accept(&chunk)?;
            }
            assert!(download.source_verified());
            verifier.finish()?;
            verified += 1;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((verified, bytes))
    });
    let loaded_started = Instant::now();
    let loaded_frames = phase(
        Duration::from_secs(4),
        &input_sender,
        &samples,
        &mut receiver,
        &mut sequence,
    )
    .await?;
    let loaded_elapsed = loaded_started.elapsed();
    let loaded_end = sequence;
    let loaded_stats = video.stats();
    let loaded_video_bps = u128::from(loaded_stats.enqueued_video_bytes.saturating_sub(baseline_stats.enqueued_video_bytes))
        * 8_000_000_000 / loaded_elapsed.as_nanos().max(1);
    eprintln!("actual file-loaded producer: {loaded_stats:?}");
    fs::write(
        root.join("pre-step-stats.txt"),
        format!("baseline={baseline_stats:?}\nfile_loaded={loaded_stats:?}\nactual_loaded_video_bps={loaded_video_bps}\n"),
    )?;
    assert!(
        loaded_frames > 20,
        "file concurrency froze actual presented video"
    );
    assert!(
        !files.is_finished(),
        "actual file flow must be active at step"
    );
    assert!(
        video
            .stats()
            .last_budget
            .ok_or("no actual budget observation")?
            .bitrate_kbps
            > 5000,
        "producer was already below step rate before physical change"
    );
    assert!(loaded_video_bps > 5_000_000, "actual video payload must exceed5Mbps before the physical step, measured={loaded_video_bps}");
    fs::write(root.join("step-request"), b"20-to-5Mbps\n")?;
    marker(&root, "stepped").await?;
    let step = Instant::now();
    let mut downshift_unix_ns = None;
    let end = step + Duration::from_secs(5);
    let mut step_frames = 0;
    let mut observations = String::new();
    let mut previous_observation = None;
    while Instant::now() < end {
        step_frames += phase(
            Duration::from_millis(25),
            &input_sender,
            &samples,
            &mut receiver,
            &mut sequence,
        )
        .await?;
        let actual = video.stats();
        if let Some(budget) = actual.last_budget
            && previous_observation != Some(budget.observed_at)
        {
            previous_observation = Some(budget.observed_at);
            observations.push_str(&format!(
                "elapsed_us={} stats={actual:?}\n",
                step.elapsed().as_micros()
            ));
            fs::write(root.join("step-budget-observations.txt"), &observations)?;
        }
        if downshift_unix_ns.is_none()
            && actual
                .last_budget
                .is_some_and(|budget| budget.observed_at >= step && budget.bitrate_kbps <= 5000)
        {
            assert!(
                step.elapsed() <= Duration::from_secs(2),
                "actual producer downshift exceeded original 2s"
            );
            downshift_unix_ns = Some(unix_ns()?);
        }
    }
    let post_step_stats = video.stats();
    eprintln!("actual stepped producer: {post_step_stats:?}; presented={step_frames}");
    fs::write(
        root.join("post-step-stats.txt"),
        format!("producer={post_step_stats:?}\npresented={step_frames}\n"),
    )?;
    let downshift_unix_ns = downshift_unix_ns.ok_or("no actual downshift within step")?;
    assert!(
        step_frames > 20,
        "step caused sustained decode/presentation freeze"
    );
    file_stop.store(true, Ordering::Release);
    let (verified_files, file_bytes) =
        tokio::time::timeout(Duration::from_secs(30), files).await???;
    assert!(
        verified_files > 0 && file_bytes >= 4 * 1024 * 1024,
        "actual original file protocol must finish SHA verification"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (baseline, loaded, impaired, raw) = {
        let samples = samples.lock().map_err(|_| "samples poisoned")?;
        (
            percentile(&samples, 0, baseline_end)?,
            percentile(&samples, baseline_end, loaded_end)?,
            percentile(&samples, loaded_end, sequence)?,
            samples
                .delivered
                .iter()
                .map(|(id, us)| format!("[{id},{us}]"))
                .collect::<Vec<_>>()
                .join(","),
        )
    };
    let producer = video.stats();
    let last_budget = producer
        .last_budget
        .ok_or("missing final actual producer budget")?;
    fs::write(
        root.join("measurement.json"),
        format!(
            "{{\"baseline_p95_us\":{baseline},\"file_p95_us\":{loaded},\"impaired_file_p95_us\":{impaired},\"downshift_unix_ns\":{downshift_unix_ns},\"verified_files\":{verified_files},\"file_bytes\":{file_bytes},\"enqueued_video_bytes\":{},\"last_bitrate_kbps\":{},\"last_cadence_fps\":{},\"presented_frames\":[{initial_frames},{loaded_frames},{step_frames}],\"input_dispatch_samples\":[{raw}]}}\n",
            producer.enqueued_video_bytes, last_budget.bitrate_kbps, last_budget.cadence_fps
        ),
    )?;
    assert!(
        loaded <= baseline + 10_000 && impaired <= baseline + 10_000,
        "input dispatch p95 increase exceeded original10ms: base={baseline} loaded={loaded} impaired={impaired}"
    );
    let _ = renewal_stop.send(());
    assert!(
        renewal.await?? > 0,
        "actual original signed lease renewal required"
    );
    pair.revoke.send_replace(Some(StopReason::Revoked));
    pair.controller_revoke
        .send_replace(Some(StopReason::Revoked));
    assert_eq!(video.shutdown(StopReason::Revoked)?, ShutdownReport::Joined);
    assert_eq!(
        receiver.shutdown(StopReason::Revoked)?,
        ShutdownReport::Joined
    );
    file_server.shutdown(StopReason::Revoked).await?;
    pair.host.wait_stopped().await?;
    tokio::time::timeout(Duration::from_secs(2), input_task).await???;
    Ok(())
}
