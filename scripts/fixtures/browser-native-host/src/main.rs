//! Local development fixture: actual management/Core/WebRTC/VP8 with owned pixels.
//! It never captures a user desktop or opens a persistent installation database.
mod multidisplay;
mod owned_cleanup;
mod owned_data;
use axum::{
    body::Body,
    extract::{Request, State},
    http::{Response, StatusCode, Uri},
    middleware::{self, Next},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_app_core::{
    BrowserHostCaptureProvider, BrowserHostChannels, BrowserHostConfig, BrowserHostDisplayApproval,
    BrowserHostError, PreparedBrowserCapture, run_browser_host,
};
use nestlink_auth::{Secret, VaultKey, random_bytes, random_id};
use nestlink_identity::{PermitSigner, VerifiedPermit};
use nestlink_media_codec::VideoConfig;
use nestlink_protocol::{
    Path, Permission,
    api::{ApprovalChoice, NodeRegistration},
    native_displays::{DisplayDescriptor, catalog_key},
};
use nestlink_remote::{
    LeaseControl,
    audio::{
        AudioBinding, AudioCaptureController, AudioCaptureDevice, AudioChunk, AudioDevice,
        CHUNK_FRAMES, CapturedAudio,
    },
    input::{InputController, InputDevice, InputEpoch, InputLayout},
    video::{CaptureDevice, Display, RawFrame, VideoController, VideoEpoch},
};
use nestlink_sdk::{
    DeploymentTrust, DeviceIdentity, Sdk,
    webrtc_host::{
        HostAudioSource, HostDataFactory, HostInputSource, HostMediaSources, HostVideoSource,
        WebRtcHostError,
    },
};
use nestlink_server::{AppState, router};
use nestlink_storage::Store;
use serde_json::json;
use std::{
    collections::HashMap,
    error::Error,
    future::Future,
    io,
    io::Write,
    path::PathBuf,
    pin::Pin,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{oneshot, watch};
use tower::ServiceExt;

type Result<T = ()> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
type Assets = HashMap<String, (String, Vec<u8>)>;

struct NegotiationLog(AtomicUsize);
static NEGOTIATION_LOG: NegotiationLog = NegotiationLog(AtomicUsize::new(0));
static NEGOTIATION_STARTED: OnceLock<Instant> = OnceLock::new();
impl log::Log for NegotiationLog {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.target() == "dtls::handshaker"
            || (metadata.target() == "webrtc::peer_connection"
                && metadata.level() <= log::Level::Info)
            || (metadata.target() == "webrtc::peer_connection::peer_connection_internal"
                && metadata.level() <= log::Level::Warn)
            || (metadata.target() == "webrtc_ice::agent::agent_internal"
                && metadata.level() <= log::Level::Warn)
    }

    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let message = record.args().to_string();
        // Audited log sites in locked dtls 0.13.0 / webrtc 0.14.0: retain
        // flight/state transitions and manager startup failures only. Never
        // enable general SDP, candidate, packet or cryptographic debug logs.
        let ice_event = if record.target() == "webrtc_ice::agent::agent_internal"
            && message.contains(": discard success message from (")
            && message.ends_with(", no such remote")
        {
            Some("ice_remote_response_unmatched")
        } else if record.target() == "webrtc_ice::agent::agent_internal"
            && message.ends_with(": Discarded message, not a valid remote candidate")
        {
            Some("ice_remote_packet_unmatched")
        } else {
            None
        };
        let event = if let Some(event) = ice_event {
            event
        } else if record.target() == "dtls::handshaker" && message.starts_with("[handshake:") {
            "dtls_flight"
        } else if record.target() == "webrtc::peer_connection"
            && (message.starts_with("ICE connection state changed:")
                || message.starts_with("peer connection state changed:")
                || message.starts_with("signaling state changed to "))
        {
            "peer_state"
        } else if message.starts_with("Failed to start manager ice:") {
            "ice_start_failed"
        } else if message.starts_with("Failed to start manager dtls:") {
            "dtls_start_failed"
        } else {
            return;
        };
        if self.0.fetch_add(1, Ordering::Relaxed) < 200 {
            // ICE sites contain endpoint addresses. Publish only their fixed
            // event category, never their formatted message or packet data.
            let bounded = ice_event
                .is_none()
                .then(|| message.chars().take(384).collect::<String>());
            let elapsed = NEGOTIATION_STARTED
                .get_or_init(Instant::now)
                .elapsed()
                .as_millis();
            eprintln!(
                "{}",
                json!({"event":event,"detail":bounded,"elapsed_since_first_event_ms":elapsed})
            );
        }
    }

    fn flush(&self) {}
}

#[derive(Default)]
struct CaptureFacts {
    prepared: AtomicBool,
    starts: AtomicUsize,
    frames: AtomicUsize,
    reset: AtomicBool,
    audio_chunks: AtomicUsize,
    audio_reset: AtomicBool,
}

struct OwnedCapture {
    facts: Arc<CaptureFacts>,
    next: Instant,
    profile: VideoConfig,
    displays: Vec<DisplayDescriptor>,
    multidisplay: Option<Arc<multidisplay::OwnedMultiDisplay>>,
    last_capture_source: Option<u32>,
}
impl CaptureDevice for OwnedCapture {
    fn check(&mut self) -> io::Result<()> {
        if self.facts.reset.load(Ordering::Acquire) {
            return Err(io::Error::other("fixture capture stopped"));
        }
        Ok(())
    }
    fn poll_frame(&mut self) -> io::Result<Option<RawFrame>> {
        self.poll_frame_for(self.displays[0].source)
    }
    fn poll_frame_for(&mut self, source: u32) -> io::Result<Option<RawFrame>> {
        self.check()?;
        let display = self
            .displays
            .iter()
            .find(|display| display.source == source)
            .ok_or_else(|| io::Error::other("fixture source was not locally approved"))?;
        if self.last_capture_source != Some(source) {
            if let Some(multi) = self.multidisplay.as_ref() {
                multi.capture_source(source);
            }
            self.last_capture_source = Some(source);
        }
        let now = Instant::now();
        if now < self.next {
            return Ok(None);
        }
        self.next = (self.next + Duration::from_nanos(1_000_000_000 / u64::from(self.profile.fps)))
            .max(now);
        let sequence = self.facts.frames.fetch_add(1, Ordering::AcqRel);
        // RawFrame is BGRA: red source 3 (and legacy source 1), blue source 8.
        let green = (sequence % 128 + 64) as u8;
        let pixel = if source == 8 {
            [210, green, 40, 255]
        } else {
            [40, green, 210, 255]
        };
        if let Some(multi) = self.multidisplay.as_ref() {
            multi.frame(source);
        }
        Ok(Some(RawFrame {
            source,
            width: display.width,
            height: display.height,
            captured_at: now,
            pixels: pixel.repeat(display.width as usize * display.height as usize),
        }))
    }
    fn discard_pending_frames(&mut self) -> io::Result<()> {
        self.check()?;
        self.next = Instant::now();
        if let Some(multi) = self.multidisplay.as_ref() {
            multi.flush();
        }
        Ok(())
    }
    fn reset(&mut self) -> io::Result<()> {
        self.facts.reset.store(true, Ordering::Release);
        Ok(())
    }
}

struct OwnedAudio {
    facts: Arc<CaptureFacts>,
    started: Instant,
    next_pts: u64,
}
impl AudioDevice for OwnedAudio {
    fn check(&mut self) -> io::Result<()> {
        if self.facts.audio_reset.load(Ordering::Acquire) {
            return Err(io::Error::other("fixture audio stopped"));
        }
        Ok(())
    }
    fn reset(&mut self) -> io::Result<()> {
        self.facts.audio_reset.store(true, Ordering::Release);
        Ok(())
    }
}
impl AudioCaptureDevice for OwnedAudio {
    fn poll_chunk(&mut self) -> io::Result<Option<CapturedAudio>> {
        self.check()?;
        let now = Instant::now();
        let elapsed = now.duration_since(self.started).as_nanos();
        let pts =
            ((elapsed * 48_000 / 1_000_000_000) as u64 / CHUNK_FRAMES as u64) * CHUNK_FRAMES as u64;
        if pts < self.next_pts {
            return Ok(None);
        }
        self.next_pts = pts + CHUNK_FRAMES as u64;
        // Owned synthetic 400 Hz PCM, never a microphone or system loopback.
        let samples = (0..CHUNK_FRAMES)
            .flat_map(|index| {
                let value = (((pts + index as u64) % 120) as i16 - 60) * 40;
                [value, value]
            })
            .collect();
        self.facts.audio_chunks.fetch_add(1, Ordering::AcqRel);
        Ok(Some(CapturedAudio {
            captured_at: now,
            chunk: AudioChunk {
                source: 1,
                channels: 2,
                pts_48khz: pts,
                samples,
            },
        }))
    }
}

struct Provider(
    Arc<CaptureFacts>,
    VideoConfig,
    bool,
    Option<Arc<owned_data::OwnedData>>,
    Option<Arc<multidisplay::OwnedMultiDisplay>>,
);
impl BrowserHostCaptureProvider for Provider {
    fn supports_audio(&self) -> bool {
        self.2
    }
    fn supports_input(&self) -> bool {
        self.3.is_some() || self.4.is_some()
    }
    fn supports_files(&self) -> bool {
        self.3.is_some()
    }
    fn prepare_data<'a>(
        &'a self,
        _request_id: &'a str,
        permit: &'a VerifiedPermit,
        _cancel: watch::Receiver<bool>,
    ) -> Pin<
        Box<
            dyn Future<Output = std::result::Result<Option<HostDataFactory>, BrowserHostError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.3
                .as_ref()
                .map(|data| data.prepare(permit).map_err(|_| BrowserHostError::Capture))
                .transpose()
        })
    }
    fn prepare<'a>(
        &'a self,
        request_id: &'a str,
        permit: &'a VerifiedPermit,
        cancel: watch::Receiver<bool>,
    ) -> Pin<
        Box<
            dyn Future<Output = std::result::Result<PreparedBrowserCapture, BrowserHostError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let binding = nestlink_app_core::browser_host_binding(request_id, permit)?;
            self.prepare_request(&binding, &permit.claims().permissions, cancel)
                .await
        })
    }
    fn prepare_request<'a>(
        &'a self,
        binding: &'a nestlink_app_core::BrowserHostBinding,
        _permissions: &'a [i32],
        _cancel: watch::Receiver<bool>,
    ) -> Pin<
        Box<
            dyn Future<Output = std::result::Result<PreparedBrowserCapture, BrowserHostError>>
                + Send
                + 'a,
        >,
    > {
        let facts = self.0.clone();
        let profile = self.1;
        let with_audio = self.2;
        let owned_data = self.3.clone();
        let multidisplay = self.4.clone();
        let displays = owned_displays(profile, multidisplay.is_some());
        let generation = binding.connection_generation;
        Box::pin(async move {
            facts.prepared.store(true, Ordering::Release);
            let prepared =
                PreparedBrowserCapture::new(displays.clone(), move |approval, lease, _permit| {
                    facts.starts.fetch_add(1, Ordering::AcqRel);
                    let approved: Vec<_> = displays
                        .into_iter()
                        .filter(|display| approval.sources.contains(&display.source))
                        .collect();
                    let catalog = catalog_key(
                        &approval.catalog.request_id,
                        approval.catalog.connection_generation,
                        approval.catalog.revision,
                        &approved,
                    )?;
                    let views: Vec<_> = approved
                        .iter()
                        .map(|display| Display {
                            source: display.source,
                            logical: InputLayout {
                                left: display.left,
                                top: display.top,
                                width: display.width,
                                height: display.height,
                            },
                        })
                        .collect();
                    let display = views
                        .iter()
                        .find(|display| display.source == approval.initial_source)
                        .copied()
                        .ok_or(WebRtcHostError::Permit)?;
                    let epoch = VideoEpoch {
                        layout: 1,
                        connection: generation,
                    };
                    let source = VideoController::attach_selected(
                        lease.clone(),
                        OwnedCapture {
                            facts: facts.clone(),
                            next: Instant::now(),
                            profile,
                            displays: approved.clone(),
                            multidisplay: multidisplay.clone(),
                            last_capture_source: None,
                        },
                        epoch,
                        views,
                        approval.initial_source,
                    )?;
                    let codec = VideoConfig {
                        width: display.logical.width,
                        height: display.logical.height,
                        ..profile
                    };
                    let video = HostVideoSource::with_display_catalog(
                        source, epoch, display, codec, catalog, approved,
                    )?;
                    let input = if let Some(data) = owned_data {
                        Some(attach_owned_input(
                            lease.clone(),
                            data.input_device(),
                            generation,
                            display,
                        )?)
                    } else if let Some(multi) = multidisplay {
                        Some(attach_owned_input(
                            lease.clone(),
                            multi.input_device(),
                            generation,
                            display,
                        )?)
                    } else {
                        None
                    };
                    let audio = if with_audio {
                        let binding = AudioBinding {
                            connection: generation,
                            source: 1,
                            channels: 2,
                        };
                        Some(HostAudioSource::new(
                            AudioCaptureController::attach(
                                lease,
                                OwnedAudio {
                                    facts,
                                    started: Instant::now(),
                                    next_pts: 0,
                                },
                                binding,
                            )?,
                            binding,
                            64_000,
                        ))
                    } else {
                        None
                    };
                    let media = HostMediaSources::new(video, audio);
                    Ok(match input {
                        Some(input) => media.with_input(input),
                        None => media,
                    })
                });
            Ok(prepared)
        })
    }
}

fn owned_displays(profile: VideoConfig, multi: bool) -> Vec<DisplayDescriptor> {
    if multi {
        multidisplay::displays()
    } else {
        vec![DisplayDescriptor {
            source: 1,
            left: 0,
            top: 0,
            width: profile.width,
            height: profile.height,
            label: "Owned synthetic display".into(),
        }]
    }
}

fn attach_owned_input<D: InputDevice>(
    lease: LeaseControl,
    mut device: D,
    generation: u64,
    display: Display,
) -> std::result::Result<HostInputSource, WebRtcHostError> {
    // Establish the adapter's initial source without advancing epochs before
    // the host's first acknowledged display transaction.
    device.select_source(display.source, display.logical)?;
    let epoch = InputEpoch {
        input: 1,
        layout: 1,
        connection: generation,
    };
    let controller = InputController::attach(lease, device, epoch, display.logical)?;
    Ok(HostInputSource::new(controller, epoch, display.logical))
}

#[derive(Clone)]
struct ManagementProbe {
    side: &'static str,
    log: Arc<Mutex<std::fs::File>>,
    started: Instant,
}

async fn record_management(
    State(probe): State<ManagementProbe>,
    request: Request,
    next: Next,
) -> axum::response::Response {
    // Retain fixed operation labels and HTTP status only. Never log IDs,
    // credentials, headers, bodies, SDP or endpoint proof messages.
    let operation = match request
        .uri()
        .path()
        .split('/')
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["", "api", "v3", "remote", _, "permit"] => Some("permit"),
        ["", "api", "v3", "remote", _, "signals"] => Some("signals"),
        ["", "api", "v3", "remote", _, "peer-keys"] => Some("peer_keys"),
        ["", "api", "v3", "remote", _, "turn-peers"] => Some("turn_peers"),
        ["", "api", "v3", "remote", _, "approval"] => Some("approval"),
        ["", "api", "v3", "remote", _, "renew"] => Some("renew"),
        ["", "api", "v3", "remote", _] => Some("remote"),
        _ => None,
    };
    let method = request.method().as_str().to_owned();
    if let Some(operation) = operation
        && let Ok(mut log) = probe.log.lock()
    {
        let record = json!({"side":probe.side,"operation":operation,"phase":"start","method":method,
            "elapsed_ms":probe.started.elapsed().as_millis()});
        let _ = writeln!(log, "{record}");
    }
    let response = next.run(request).await;
    if let Some(operation) = operation {
        let record = json!({"side":probe.side,"operation":operation,"method":method,
            "phase":"end","status":response.status().as_u16(),"elapsed_ms":probe.started.elapsed().as_millis()});
        if let Ok(mut log) = probe.log.lock() {
            let _ = writeln!(log, "{record}");
        }
    }
    response
}

fn load_assets(root: &std::path::Path) -> Result<Assets> {
    let mut assets = HashMap::new();
    let mut pending = vec![root.to_owned()];
    let mut total = 0u64;
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            let metadata = entry.file_type()?;
            if metadata.is_symlink() {
                return Err(io::Error::other("static asset symlink rejected").into());
            }
            if metadata.is_dir() {
                pending.push(entry.path());
                continue;
            }
            if !metadata.is_file() {
                return Err(io::Error::other("special static asset rejected").into());
            }
            let bytes = std::fs::read(entry.path())?;
            total += bytes.len() as u64;
            if total > 64 * 1024 * 1024 {
                return Err(io::Error::other("static site exceeds fixture budget").into());
            }
            let key = format!(
                "/{}",
                entry
                    .path()
                    .strip_prefix(root)?
                    .to_string_lossy()
                    .replace('\\', "/")
            );
            let mime = match entry.path().extension().and_then(|value| value.to_str()) {
                Some("html") => "text/html; charset=utf-8",
                Some("js") => "text/javascript; charset=utf-8",
                Some("wasm") => "application/wasm",
                Some("css") => "text/css; charset=utf-8",
                Some("svg") => "image/svg+xml",
                Some("woff2") => "font/woff2",
                _ => "application/octet-stream",
            };
            assets.insert(key, (mime.into(), bytes));
        }
    }
    if !assets.contains_key("/index.html") {
        return Err(io::Error::other("production index is absent").into());
    }
    Ok(assets)
}

async fn run() -> Result {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if !(3..=8).contains(&arguments.len()) {
        return Err("usage: fixture <production-static-site> <new-evidence-directory> <loopback-https-origin> [smoke|1080p30] [duration-seconds] [audio] [owned-data] [multi-display]".into());
    }
    let profile_name = arguments
        .get(3)
        .and_then(|value| value.to_str())
        .unwrap_or("smoke");
    let profile = match profile_name {
        "smoke" => VideoConfig {
            width: 320,
            height: 180,
            fps: 10,
            bitrate_kbps: 250,
        },
        "1080p30" => VideoConfig {
            width: 1920,
            height: 1080,
            fps: 30,
            bitrate_kbps: 4_000,
        },
        _ => return Err("unknown owned capture profile".into()),
    };
    let duration_seconds = arguments
        .get(4)
        .map(|value| {
            value
                .to_str()
                .ok_or("invalid duration")?
                .parse::<u64>()
                .map_err(|_| "invalid duration")
        })
        .transpose()?
        .unwrap_or(36);
    if !(36..=1800).contains(&duration_seconds) {
        return Err("duration must be between 36 and 1800 seconds".into());
    }
    let mut with_audio = false;
    let mut with_data = false;
    let mut with_multidisplay = false;
    for flag in arguments.iter().skip(5).map(|value| value.to_str()) {
        match flag {
            Some("audio") if !with_audio => with_audio = true,
            Some("owned-data") if !with_data => with_data = true,
            Some("multi-display") if !with_multidisplay => with_multidisplay = true,
            _ => return Err("unknown or duplicate owned fixture profile".into()),
        }
    }
    if with_multidisplay && (profile_name != "smoke" || with_audio || with_data) {
        return Err("multi-display requires smoke without audio or owned-data".into());
    }
    let mut permissions = vec![Permission::View as i32];
    if with_audio {
        permissions.push(Permission::Audio as i32);
    }
    if with_data {
        permissions.extend([
            Permission::Input as i32,
            Permission::FileRead as i32,
            Permission::FileWrite as i32,
        ]);
    }
    if with_multidisplay {
        permissions.push(Permission::Input as i32);
    }
    permissions.sort_unstable();
    // The space lifecycle crosses the production 30 requests / 60 seconds
    // window before media starts. Reserve that management setup time in the
    // original fixture envelope; steady media and cleanup budgets stay intact.
    let management_rate_window_seconds = 61;
    let lifetime = Duration::from_secs(duration_seconds + 84 + management_rate_window_seconds);
    let site = PathBuf::from(&arguments[0]).canonicalize()?;
    let evidence = PathBuf::from(&arguments[1]);
    std::fs::create_dir(&evidence)?;
    let owned_data = with_data
        .then(|| owned_data::OwnedData::new(&evidence))
        .transpose()?;
    let owned_multidisplay = with_multidisplay
        .then(|| multidisplay::OwnedMultiDisplay::new(&evidence))
        .transpose()?;
    let browser_origin = arguments[2].to_str().ok_or("invalid HTTPS origin")?;
    let tls_port: u16 = browser_origin
        .strip_prefix("https://127.0.0.1:")
        .ok_or("fixture requires loopback HTTPS")?
        .parse()?;
    if tls_port == 0 {
        return Err("fixture requires a nonzero TLS port".into());
    }
    let assets = Arc::new(load_assets(&site)?);
    let management_log = Arc::new(Mutex::new(
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(evidence.join("management-stages.jsonl"))?,
    ));
    let probe_started = Instant::now();
    let deployment_id = random_id();
    let signing_seed = random_bytes::<32>();
    let signer = PermitSigner::from_seed(signing_seed);
    let permit_issuer = signer.public_key();
    let vault_seed = random_bytes::<32>();
    let password = format!("fixture-{}", random_id());
    let scratch = tempfile::Builder::new()
        .prefix("nestlink-browser-native-")
        .tempdir()?;
    let database = scratch.path().join("fixture.sqlite3");
    let mut store = Store::open(&database, &deployment_id)?;
    store.bootstrap_admin("fixture-admin", &password)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let control_state = AppState::new(
        store,
        VaultKey::from_bytes(vault_seed),
        signer,
        origin.clone(),
        false,
    )?;
    let native_app = router(control_state.clone()).layer(middleware::from_fn_with_state(
        ManagementProbe {
            side: "native",
            log: management_log.clone(),
            started: probe_started,
        },
        record_management,
    ));
    // Both entries share one control runtime and its event/relay owners. Each
    // signs its configured origin; HTTPS and secure cookies remain enabled.
    let browser_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let browser_backend_origin = format!("http://{}", browser_listener.local_addr()?);
    // Explicit fixture proxy: namespace writes use a configured DNS management
    // entry sharing the real Store; production DNS/origin validation stays intact.
    let namespace_entry =
        router(control_state.for_management_entry("https://manage.example.test".into(), true));
    let app = router(control_state.for_management_entry(browser_origin.to_owned(), true))
        .fallback(move |uri: Uri| {
            let assets = assets.clone();
            async move {
                let key = if uri.path() == "/" {
                    "/index.html"
                } else {
                    uri.path()
                };
                match assets.get(key) {
                    Some((mime, bytes)) => Response::builder()
                        .header("Content-Type", mime)
                        .header("Cache-Control", "no-store")
                        .body(Body::from(bytes.clone())),
                    None => Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Body::empty()),
                }
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
            }
        })
        .layer(middleware::from_fn_with_state(
            ManagementProbe {
                side: "browser",
                log: management_log,
                started: probe_started,
            },
            record_management,
        ))
        .layer(middleware::from_fn(
            move |mut request: Request, next: Next| {
                let entry = namespace_entry.clone();
                async move {
                    if request.uri().path().ends_with("/service-namespace") {
                        let delay = request.method() == axum::http::Method::GET;
                        request.headers_mut().insert(
                            "origin",
                            axum::http::HeaderValue::from_static("https://manage.example.test"),
                        );
                        // This test proxy starts another routing pass. Axum's
                        // private path parameters from the outer Router must
                        // not be appended to the inner Router's parameters.
                        request.extensions_mut().clear();
                        let response = match entry.oneshot(request).await {
                            Ok(response) => response,
                            Err(never) => match never {},
                        };
                        // Delay an actual server response, never synthesize its body/status.
                        if delay {
                            tokio::time::sleep(Duration::from_millis(750)).await;
                        }
                        response
                    } else {
                        let delay_management_read = request.method() == axum::http::Method::GET
                            && (request.uri().path().starts_with("/api/v3/network/spaces/")
                                || (request.uri().path().starts_with("/api/v3/nodes/")
                                    && request.uri().path().ends_with("/relay-attributes")));
                        let response = next.run(request).await;
                        // Lifecycle checks leave/logout the actual UI before
                        // this real server response reaches its SDK.
                        if delay_management_read {
                            tokio::time::sleep(Duration::from_millis(750)).await;
                        }
                        response
                    }
                }
            },
        ));
    // The two routers now own the shared runtime. Release this setup owner so
    // joining both servers also releases the SQLite handle before cleanup.
    drop(control_state);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(listener, native_app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
    });
    let (browser_shutdown_tx, browser_shutdown_rx) = oneshot::channel();
    let browser_server = tokio::spawn(async move {
        axum::serve(browser_listener, app)
            .with_graceful_shutdown(async {
                let _ = browser_shutdown_rx.await;
            })
            .await
    });
    let result = async {
        let mut sdk = Sdk::connect(&origin, DeploymentTrust { deployment_id: deployment_id.clone(), permit_issuer }, true).await?;
        sdk.login("fixture-admin".into(), Secret::from_text(password.clone()), None).await?;
        let mut edge_nodes = Vec::new();
        for name in ["Owned namespace edge A", "Owned namespace edge B"] {
            let id = random_id();
            sdk.register_node(NodeRegistration { id: id.clone(), name: name.into(), public_key: URL_SAFE_NO_PAD.encode(random_bytes::<32>()), roles: vec![2], max_connections: 8, bytes_per_second: 1048576 }).await?;
            edge_nodes.push(json!({"id":id,"name":name}));
        }
        // A separate actual relay registration owns the metadata UI exercise.
        // It never starts a relay process or supplies forwarding authority.
        let relay_id = random_id();
        let relay_name = "Owned relay attributes node";
        sdk.register_node(NodeRegistration {
            id: relay_id.clone(),
            name: relay_name.into(),
            public_key: URL_SAFE_NO_PAD.encode(random_bytes::<32>()),
            roles: vec![nestlink_protocol::NodeRole::NodeRelay as i32],
            max_connections: 8,
            bytes_per_second: 1048576,
        }).await?;
        let installation = Arc::new(DeviceIdentity::generate());
        let mut capabilities = vec!["host".into(), "vp8".into()];
        if with_audio { capabilities.push("opus".into()); }
        let platform = match std::env::consts::OS {
            "windows" => "windows",
            "linux" => "linux-x11",
            _ => return Err("owned native fixture requires Windows or Linux".into()),
        };
        sdk.enroll(&installation, "Owned synthetic media fixture".into(), platform.into(), capabilities, "direct_only".into()).await?;
        let ready = json!({"scope":"Ephemeral local development fixture; synthetic owned pixels, real Core/WebRTC/VP8", "origin":browser_origin, "native_management_origin":origin, "browser_backend_origin":browser_backend_origin, "deployment_id":deployment_id, "permit_issuer":URL_SAFE_NO_PAD.encode(permit_issuer), "username":"fixture-admin", "password":password, "host_device_id":installation.device_id,
            "capture_profile":{"name":profile_name,"width":profile.width,"height":profile.height,"fps":profile.fps,"duration_seconds":duration_seconds,"lifetime_seconds":lifetime.as_secs(),"management_rate_window_seconds":management_rate_window_seconds,"with_audio":with_audio},
            "edge_namespace":{"management_hostname":"manage.example.test","nodes":edge_nodes},
            "relay_attributes":{"node":{"id":relay_id,"name":relay_name}},
            "owned_data":owned_data.as_ref().map(|data| data.descriptor()),
            "owned_multidisplay":owned_multidisplay.as_ref().map(|multi| multi.descriptor())});
        std::fs::write(evidence.join("ready.json"), serde_json::to_vec_pretty(&ready)?)?;
        let deadline = probe_started + lifetime;
        let request = loop {
            if Instant::now() >= deadline || evidence.join("stop.request").exists() { return Err("no fixture request before shutdown".into()); }
            if let Some(request) = sdk.pending_remote().await?.into_iter().find(|request| request.host_device_id == installation.device_id) { break request; }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        if !matches_owned_permissions(&request.permissions, &permissions) || request.paths != vec![Path::Direct as i32] { return Err("fixture only approves its exact owned media/direct request".into()); }
        sdk.approve(&installation, &request, ApprovalChoice { approved: true, permissions: permissions.clone(), paths: vec![Path::Direct as i32] }).await?;
        // Mirror the product's automatic pre-lease host preparation.
        let approved = sdk.remote(&request.id).await?;
        std::fs::write(evidence.join("host-start-gate.json"), serde_json::to_vec_pretty(&json!({
            "approved":true,"controller_issued_initial_lease":false,
            "lease_sequence":approved.lease_sequence,"connection_generation":approved.connection_generation,
            "elapsed_ms":probe_started.elapsed().as_millis()
        }))?)?;
        let facts = Arc::new(CaptureFacts::default());
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let (ready_tx, ready_rx) = oneshot::channel();
        let (display_offer_tx, display_offer_rx) = oneshot::channel();
        let (display_approval_tx, display_approval_rx) = watch::channel(None);
        let config = BrowserHostConfig::new(Arc::new(Provider(
            facts.clone(),
            profile,
            with_audio,
            owned_data.clone(),
            owned_multidisplay.clone(),
        )));
        let channels = BrowserHostChannels {
            cancel: cancel_rx,
            display_offer: display_offer_tx,
            display_approval: display_approval_rx,
            ready: ready_tx,
        };
        let mut host = Box::pin(run_browser_host(sdk, installation, request.id, config, channels));
        let mut display_offer_rx = Box::pin(display_offer_rx);
        let mut display_offer_received = false;
        let mut ready_rx = Box::pin(ready_rx);
        let mut connected = false;
        let mut readiness_received = false;
        let exit = loop {
            tokio::select! {
                result = &mut host => break result,
                result = &mut display_offer_rx, if !display_offer_received => {
                    display_offer_received = true;
                    if let Ok(offer) = result {
                        if offer.displays != owned_displays(profile, with_multidisplay) {
                            cancel_tx.send_replace(true);
                            continue;
                        }
                        let sources: Vec<_> = offer.displays.iter().map(|display| display.source).collect();
                        let initial_source = if with_multidisplay { 8 } else { 1 };
                        let approval = BrowserHostDisplayApproval {
                            binding: offer.binding, catalog: offer.catalog,
                            sources: sources.clone(), initial_source,
                        };
                        let mut output = std::fs::OpenOptions::new().create_new(true).write(true)
                            .open(evidence.join("display-approval.json"))?;
                        serde_json::to_writer_pretty(&mut output, &json!({
                            "scope":"Explicit owned fixture approval; no OS capture or input",
                            "binding":approval.binding,"catalog":approval.catalog,
                            "approved_sources":sources,"initial_source":initial_source,
                            "displays":offer.displays,"elapsed_ms":probe_started.elapsed().as_millis()
                        }))?;
                        writeln!(output)?;
                        display_approval_tx.send_replace(Some(approval));
                    } else { cancel_tx.send_replace(true); }
                }
                result = &mut ready_rx, if !readiness_received => {
                    readiness_received = true;
                    connected = matches!(result, Ok(Ok(_)));
                    if connected {
                        std::fs::write(evidence.join("connected.json"), b"{\"connected\":true}\n")?;
                    } else {
                        cancel_tx.send_replace(true);
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    if evidence.join("stop.request").exists() || Instant::now() >= deadline { cancel_tx.send_replace(true); }
                }
            }
        };
        let audio_clean = !with_audio || (facts.audio_chunks.load(Ordering::Acquire) > 0 && facts.audio_reset.load(Ordering::Acquire));
        let host_connected = exit.connected;
        let cleanup_failed = exit.cleanup_failed;
        let diagnostic = exit.diagnostic;
        let result = json!({
            "scope":"Local synthetic-capture Core/WebRTC integration, not installed-platform acceptance",
            "connected":connected && exit.connected,
            "cleanup_failed":exit.cleanup_failed,
            "failure":format!("{:?}", exit.failure),
            "diagnostic":diagnostic.map(|diagnostic| json!({
                "stage":format!("{:?}", diagnostic.stage),
                "source":format!("{:?}", diagnostic.source),
                "elapsed_ms":diagnostic.elapsed_ms,
                "peer":diagnostic.peer.map(|peer| json!({
                    "reason":format!("{:?}", peer.reason),
                    "io_error_kind":peer.io_error_kind.map(|kind| format!("{kind:?}")),
                    "elapsed_ms":peer.elapsed_ms
                }))
            })),
            "capture_prepared":facts.prepared.load(Ordering::Acquire),
            "capture_starts":facts.starts.load(Ordering::Acquire),
            "capture_frames":facts.frames.load(Ordering::Acquire),
            "capture_reset":facts.reset.load(Ordering::Acquire),
            "audio_enabled":with_audio,
            "audio_chunks":facts.audio_chunks.load(Ordering::Acquire),
            "audio_reset":facts.audio_reset.load(Ordering::Acquire),
            "audio_cleanup_succeeded":audio_clean
        });
        std::fs::write(evidence.join("host-result.json"), serde_json::to_vec_pretty(&result)?)?;
        // Drop the completed future, its factory and returned SDK/lease registry
        // before proving the recording device is physically released.
        drop(host);
        drop(exit);
        if let Some(data) = owned_data.as_ref()
            && !data.finish(&evidence, !cleanup_failed)?
        {
            return Err("owned data did not exercise and clean its exact input/files".into());
        }
        if let Some(multi) = owned_multidisplay.as_ref()
            && !multi.finish(&evidence, !cleanup_failed)?
        {
            return Err("owned multi-display selection/input did not exercise and clean its exact sources".into());
        }
        if !host_connected || cleanup_failed || facts.starts.load(Ordering::Acquire) != 1 || !facts.reset.load(Ordering::Acquire) || !audio_clean { return Err("native host did not connect and clean up its owned media sources".into()); }
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    }.await;
    // Keep management available for the production UI's revoke and device
    // cleanup even if the native host failed first. Preserve the original
    // lifetime, then close both servers before removing the owned database.
    let management_deadline = probe_started + lifetime;
    while !evidence.join("stop.request").exists() && Instant::now() < management_deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let _ = shutdown_tx.send(());
    let _ = browser_shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), server).await???;
    tokio::time::timeout(Duration::from_secs(5), browser_server).await???;
    owned_cleanup::close(scratch, &evidence).await?;
    result
}

fn matches_owned_permissions(requested: &[i32], expected_sorted: &[i32]) -> bool {
    // The API preserves UI order; permissions are an exact set. Sorting only
    // this copy preserves duplicate/extra/missing permission rejection.
    let mut requested = requested.to_vec();
    requested.sort_unstable();
    requested == expected_sorted
}

#[tokio::main]
async fn main() -> Result {
    log::set_logger(&NEGOTIATION_LOG).map_err(|_| "fixture negotiation logger unavailable")?;
    log::set_max_level(log::LevelFilter::Trace);
    run().await
}

#[cfg(test)]
mod permission_tests {
    use super::matches_owned_permissions;
    use nestlink_protocol::Permission;

    #[test]
    fn ui_audio_input_order_retains_exact_owned_approval() {
        let expected = [
            Permission::View as i32,
            Permission::Input as i32,
            Permission::Audio as i32,
            Permission::FileRead as i32,
            Permission::FileWrite as i32,
        ];
        let ui_request = [
            expected[0],
            expected[2],
            expected[1],
            expected[3],
            expected[4],
        ];
        assert!(matches_owned_permissions(&ui_request, &expected));
        assert!(!matches_owned_permissions(&ui_request[..4], &expected));
        let mut extra = ui_request.to_vec();
        extra.push(Permission::ClipboardWrite as i32);
        assert!(!matches_owned_permissions(&extra, &expected));
        extra[5] = Permission::Input as i32;
        assert!(!matches_owned_permissions(&extra, &expected));
        let mut replacement = ui_request;
        replacement[4] = Permission::ClipboardWrite as i32;
        assert!(!matches_owned_permissions(&replacement, &expected));
    }
}
