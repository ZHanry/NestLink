//! Owned software graph + actual production logind/audio APIs in namespaces.
use super::*;
use nestlink_auth::random_id;
use nestlink_identity::{InstallationIdentity, PermitSigner, verify_permit};
use nestlink_policy::PathSet;
use nestlink_protocol::{Path as Route, Permission, PermitClaims};
use nestlink_remote::{
    AuthorizedConnection, ChannelRuntime, RuntimeClock, SessionLifecycle,
    audio::{AudioCaptureController, AudioPlaybackController},
};
use nestlink_session::{EndpointRole, Session as BusinessSession, SessionBinding, StopReason};
use prost::Message;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    process::{Child, Command, Output, Stdio},
};
use tokio::sync::watch;
use zbus::{Connection, connection::Builder, interface, zvariant::OwnedObjectPath};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn approved() -> Result<(
    ChannelRuntime,
    watch::Sender<Option<StopReason>>,
    tokio::io::DuplexStream,
)> {
    let controller = InstallationIdentity::generate();
    let host = InstallationIdentity::generate();
    let clock = RuntimeClock::default();
    let now = clock.sample()?;
    let binding = SessionBinding {
        deployment_id: random_id(),
        security_epoch: 1,
        session_id: random_id(),
        account_id: random_id(),
        controller_device_id: random_id(),
        host_device_id: random_id(),
        controller_key_sha256: controller.fingerprint(),
        host_key_sha256: host.fingerprint(),
        resource_id: random_id(),
        policy_revision: 1,
        connection_generation: 9,
        capability_sha256: [9; 32],
        granted_permissions: vec![Permission::View, Permission::Audio],
        supported_capabilities: vec!["opus".into()],
        local_paths: PathSet::DIRECT,
    };
    let claims = PermitClaims {
        schema_version: 1,
        deployment_id: binding.deployment_id.clone(),
        security_epoch: 1,
        session_id: binding.session_id.clone(),
        account_id: binding.account_id.clone(),
        controller_device_id: binding.controller_device_id.clone(),
        host_device_id: binding.host_device_id.clone(),
        controller_key_sha256: controller.fingerprint().to_vec(),
        host_key_sha256: host.fingerprint().to_vec(),
        resource_id: binding.resource_id.clone(),
        permissions: vec![Permission::View as i32, Permission::Audio as i32],
        paths: vec![Route::Direct as i32],
        policy_revision: 1,
        connection_generation: 9,
        lease_sequence: 1,
        issued_at_unix_ms: now.unix_ms,
        expires_at_unix_ms: now.unix_ms + 15000,
        capability_sha256: vec![9; 32],
        required_capabilities: vec!["opus".into()],
    };
    let signer = PermitSigner::generate();
    let mut session = BusinessSession::activate(
        verify_permit(&signer.sign(&claims)?.encode_to_vec(), &signer.public_key())?,
        binding,
        Route::Direct,
        now.monotonic_ms,
        now,
    )?;
    for (role, identity) in [
        (EndpointRole::Controller, controller),
        (EndpointRole::Host, host),
    ] {
        session.confirm_endpoint(
            role,
            &identity.public_key(),
            &identity.prove(&session.proof_transcript())?,
            clock.monotonic_ms(),
        )?;
    }
    let (stop, stopped) = watch::channel(None);
    let (peer, stream) = tokio::io::duplex(64);
    let (read, write) = tokio::io::split(stream);
    let runtime = AuthorizedConnection::with_lifecycle(
        read,
        write,
        session,
        Route::Direct,
        clock,
        SessionLifecycle::new(stopped),
    )?
    .into_channels();
    Ok((runtime, stop, peer))
}

fn isolated() -> Result {
    let originals: serde_json::Value =
        serde_json::from_str(&std::env::var("NESTLINK_TEST_AUDIO_NAMESPACES")?)?;
    for name in ["mnt", "net", "user"] {
        let current = fs::read_link(format!("/proc/self/ns/{name}"))?;
        assert_ne!(
            current.to_string_lossy(),
            originals[name].as_str().ok_or("missing namespace")?
        );
    }
    // SAFETY: scalar identity query. This fixture is mapped to root in a fresh
    // user namespace solely to provide its own root-owned system bus.
    assert_eq!(unsafe { libc::geteuid() }, 0);
    Ok(())
}
struct Manager;
#[interface(name = "org.freedesktop.login1.Manager")]
impl Manager {
    #[zbus(name = "GetSessionByPID")]
    fn session_by_pid(&self, pid: u32) -> zbus::fdo::Result<OwnedObjectPath> {
        if pid != std::process::id() {
            return Err(zbus::fdo::Error::InvalidArgs("wrong local GUI PID".into()));
        }
        OwnedObjectPath::try_from("/org/freedesktop/login1/session/audio")
            .map_err(|error| zbus::fdo::Error::Failed(error.to_string()))
    }
}
struct Session {
    kind: &'static str,
    locked: Arc<AtomicBool>,
}
#[interface(name = "org.freedesktop.login1.Session")]
impl Session {
    #[zbus(property)]
    fn active(&self) -> bool {
        true
    }
    #[zbus(property)]
    fn locked_hint(&self) -> bool {
        self.locked.load(Ordering::SeqCst)
    }
    #[zbus(property)]
    fn r#type(&self) -> &str {
        self.kind
    }
    #[zbus(property)]
    fn class(&self) -> &str {
        "user"
    }
    #[zbus(property)]
    fn display(&self) -> &str {
        if self.kind == "x11" { ":47" } else { "" }
    }
    #[zbus(property)]
    fn user(&self) -> zbus::fdo::Result<(u32, OwnedObjectPath)> {
        Ok((
            0,
            OwnedObjectPath::try_from("/user/audio")
                .map_err(|error| zbus::fdo::Error::Failed(error.to_string()))?,
        ))
    }
}
struct Login {
    conn: Connection,
    locked: Arc<AtomicBool>,
}
impl Login {
    async fn new(kind: &'static str) -> Result<Self> {
        let locked = Arc::new(AtomicBool::new(false));
        let conn = Builder::address("unix:path=/run/dbus/system_bus_socket")?
            .auth_mechanism(zbus::AuthMechanism::External)
            .name("org.freedesktop.login1")?
            .serve_at("/org/freedesktop/login1", Manager)?
            .serve_at(
                "/org/freedesktop/login1/session/audio",
                Session {
                    kind,
                    locked: locked.clone(),
                },
            )?
            .build()
            .await?;
        Ok(Self { conn, locked })
    }
    async fn pulse(&self) -> Result {
        for locked in [true, false] {
            self.conn
                .emit_signal(
                    None::<&str>,
                    "/org/freedesktop/login1/session/audio",
                    "org.freedesktop.DBus.Properties",
                    "PropertiesChanged",
                    &(
                        "org.freedesktop.login1.Session",
                        std::collections::HashMap::from([(
                            "LockedHint",
                            zbus::zvariant::OwnedValue::from(locked),
                        )]),
                        Vec::<String>::new(),
                    ),
                )
                .await?;
        }
        Ok(())
    }
}
struct Daemon {
    directory: tempfile::TempDir,
    child: Child,
}
impl Daemon {
    fn new() -> Result<Self> {
        Self::with_format(48000, false)
    }
    fn with_format(rate: u32, multichannel: bool) -> Result<Self> {
        let directory = tempfile::Builder::new()
            .prefix("nestlink-audio-owned-")
            .tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let config = directory.path().join("audio.conf");
        let mut configuration = include_str!("../../tests/pipewire-audio-owned.conf")
            .replace(
                "default.clock.rate = 48000",
                &format!(
                    "default.clock.rate = {rate}\n    default.clock.allowed-rates = [ {rate} ]"
                ),
            )
            .replace("quantum = 960", &format!("quantum = {}", rate / 50));
        if multichannel {
            configuration = configuration.replace(
                "audio.position = [ FL FR ]",
                "audio.position = [ FL FR FC LFE RL RR ]",
            );
        }
        fs::write(&config, configuration)?;
        let log = File::create(directory.path().join("daemon.log"))?;
        let child = Command::new("pipewire")
            .args(["--config"])
            .arg(&config)
            .env("XDG_RUNTIME_DIR", directory.path())
            .env("PIPEWIRE_RUNTIME_DIR", directory.path())
            .env_remove("PIPEWIRE_REMOTE")
            .env_remove("DBUS_SESSION_BUS_ADDRESS")
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()?;
        let mut daemon = Self { directory, child };
        let until = Instant::now() + STARTUP;
        while !daemon.directory.path().join("pipewire-0").exists() {
            if daemon.child.try_wait()?.is_some() || Instant::now() >= until {
                return Err(format!(
                    "owned audio server failed: {}",
                    fs::read_to_string(daemon.directory.path().join("daemon.log"))?
                )
                .into());
            }
            thread::sleep(Duration::from_millis(5));
        }
        Ok(daemon)
    }
    fn command(&self, program: &str) -> Command {
        let mut command = Command::new(program);
        command
            .env("XDG_RUNTIME_DIR", self.directory.path())
            .env("PIPEWIRE_RUNTIME_DIR", self.directory.path())
            .env("PIPEWIRE_REMOTE", "pipewire-0");
        command
    }
    fn run(&self, mut command: Command) -> Result<Output> {
        let stdout = tempfile::NamedTempFile::new_in(self.directory.path())?;
        let stderr = tempfile::NamedTempFile::new_in(self.directory.path())?;
        let mut child = command
            .stdout(Stdio::from(stdout.reopen()?))
            .stderr(Stdio::from(stderr.reopen()?))
            .spawn()?;
        let until = Instant::now() + Duration::from_secs(2);
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Instant::now() >= until
                || stdout.as_file().metadata()?.len() > 4 * 1024 * 1024
                || stderr.as_file().metadata()?.len() > 65536
            {
                let _ = child.kill();
                let _ = child.wait();
                return Err("owned audio tool exceeded budget".into());
            }
            thread::sleep(Duration::from_millis(5));
        };
        Ok(Output {
            status,
            stdout: fs::read(stdout.path())?,
            stderr: fs::read(stderr.path())?,
        })
    }
    fn link(&self, capture: bool, channels: u8, wrong: bool) -> Result {
        let until = Instant::now() + STARTUP;
        for channel in 0..channels {
            let speaker = if channel == 0 { "FL" } else { "FR" };
            let stream = if channels == 1 { "MONO" } else { speaker };
            let mut command = self.command("pw-link");
            let source = if capture {
                format!(
                    "{}:monitor_{speaker}",
                    if wrong {
                        "nestlink-other-sink"
                    } else {
                        "nestlink-selected-sink"
                    }
                )
            } else {
                format!("nestlink-system-audio-playback:output_{stream}")
            };
            let target = if capture {
                format!("nestlink-system-audio-capture:input_{stream}")
            } else {
                format!("nestlink-selected-sink:playback_{speaker}")
            };
            loop {
                command.args([&source, &target]);
                let result = self.run(command)?;
                if result.status.success() {
                    break;
                }
                if Instant::now() >= until {
                    let mut inventory = self.command("pw-link");
                    inventory.args(["-I", "-o", "-i"]);
                    let ports = self.run(inventory)?;
                    return Err(format!(
                        "owned audio link failed: {}; ports: {}",
                        String::from_utf8_lossy(&result.stderr),
                        String::from_utf8_lossy(&ports.stdout)
                    )
                    .into());
                }
                thread::sleep(Duration::from_millis(10));
                command = self.command("pw-link");
            }
        }
        Ok(())
    }
    fn open_capture(
        &self,
        endpoint: LinuxAudioEndpoint,
        binding: AudioBinding,
        wrong: bool,
    ) -> Result<LinuxAudioCapture> {
        thread::scope(|scope| {
            let open = scope.spawn(move || LinuxAudioCapture::open(endpoint, binding));
            let link = self.link(true, binding.channels, wrong);
            let device = open.join().map_err(|_| "capture opener panicked")?;
            if let Err(error) = &device {
                eprintln!("owned native capture open: {error}");
            }
            link?;
            device.map_err(Into::into)
        })
    }
    fn open_playback(
        &self,
        endpoint: LinuxAudioEndpoint,
        binding: AudioBinding,
    ) -> Result<LinuxAudioPlayback> {
        thread::scope(|scope| {
            let open = scope.spawn(move || LinuxAudioPlayback::open(endpoint, binding));
            let link = self.link(false, binding.channels, false);
            let device = open.join().map_err(|_| "playback opener panicked")?;
            if let Err(error) = &device {
                eprintln!("owned native playback open: {error}");
            }
            link?;
            device.map_err(Into::into)
        })
    }
    fn gone(&self) -> Result {
        let until = Instant::now() + STARTUP;
        loop {
            let result = self.run(self.command("pw-dump"))?;
            assert!(result.status.success());
            let objects: serde_json::Value = serde_json::from_slice(&result.stdout)?;
            if !objects
                .as_array()
                .ok_or("bad owned inventory")?
                .iter()
                .any(|v| {
                    v["info"]["props"]["node.name"]
                        .as_str()
                        .is_some_and(|name| name.starts_with("nestlink-system-audio-"))
                })
            {
                return Ok(());
            }
            assert!(Instant::now() < until, "old audio stream survived cleanup");
            thread::sleep(Duration::from_millis(5));
        }
    }
    fn stop(&mut self) -> Result {
        self.child.kill()?;
        self.child.wait()?;
        Ok(())
    }
}
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn tone(binding: AudioBinding, pts: u64) -> AudioChunk {
    AudioChunk {
        source: binding.source,
        channels: binding.channels,
        pts_48khz: pts,
        samples: (0..CHUNK_FRAMES)
            .flat_map(|i| {
                (0..binding.channels).map(move |channel| {
                    let frequency = if channel == 0 { 440.0 } else { 880.0 };
                    (12000.0
                        * ((pts + i as u64) as f64 * frequency * std::f64::consts::TAU / 48000.0)
                            .sin()) as i16
                })
            })
            .collect(),
    }
}
fn amplitude(pcm: &[i16], channels: u8, channel: usize, hz: f64) -> f64 {
    let values = pcm.iter().skip(channel).step_by(usize::from(channels));
    let length = values.clone().count() as f64;
    let (mut sin, mut cos) = (0.0, 0.0);
    for (i, sample) in values.enumerate() {
        let angle = i as f64 * hz * std::f64::consts::TAU / 48000.0;
        sin += f64::from(*sample) * angle.sin();
        cos += f64::from(*sample) * angle.cos();
    }
    2.0 * sin.hypot(cos) / length
}
async fn sample_flow(
    capture: &AudioCaptureController<LinuxAudioCapture>,
    playback: &AudioPlaybackController<LinuxAudioPlayback>,
    binding: AudioBinding,
    label: &str,
) -> Result<u64> {
    let mut pcm = Vec::new();
    let mut last_pts = None;
    let started = Instant::now();
    let until = started + Duration::from_secs(2);
    let mut next_write = started;
    let mut pts = 0;
    while Instant::now() < until {
        if Instant::now() >= next_write {
            playback.play(&tone(binding, pts))?;
            pts += CHUNK_FRAMES as u64;
            next_write += Duration::from_millis(20);
        }
        if let Some(chunk) = capture.poll()? {
            chunk.chunk.validate(binding)?;
            assert!(last_pts.is_none_or(|pts| chunk.chunk.pts_48khz > pts));
            last_pts = Some(chunk.chunk.pts_48khz);
            pcm.extend_from_slice(&chunk.chunk.samples);
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert!(
        pcm.len() >= 48000 * usize::from(binding.channels),
        "no sustained owned audio flow: {} samples",
        pcm.len()
    );
    for channel in 0..usize::from(binding.channels) {
        let expected = if channel == 0 { 440.0 } else { 880.0 };
        let level = amplitude(&pcm, binding.channels, channel, expected);
        println!(
            "{label} {}ch synthetic output: channel {channel}, amplitude {level:.1}, {} PCM frames",
            binding.channels,
            pcm.len() / usize::from(binding.channels)
        );
        assert!(
            level > 1000.0,
            "selected sink produced no matching synthetic tone"
        );
    }
    Ok(pts)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires scripts/refactor-linux-audio.py and fresh service namespaces"]
async fn production_linux_audio_private_services() -> Result {
    isolated()?;
    for kind in ["x11", "wayland"] {
        let login = Login::new(kind).await?;
        for channels in [1, 2] {
            let daemon = Daemon::new()?;
            let desktop = Arc::new(if kind == "x11" {
                LinuxDesktopSession::open(std::process::id(), ":47")?
            } else {
                LinuxDesktopSession::open_wayland(std::process::id())?
            });
            let endpoints =
                LinuxAudioEndpoint::enumerate_at(desktop.clone(), daemon.directory.path())?;
            assert_eq!(
                endpoints.len(),
                2,
                "inventory must exclude the synthetic microphone-class node"
            );
            let endpoint = endpoints
                .into_iter()
                .find(|v| v.name() == "nestlink-selected-sink")
                .ok_or("selected sink absent")?;
            let binding = AudioBinding {
                source: 7,
                channels,
                connection: 9,
            };
            let capture = daemon.open_capture(endpoint.clone(), binding, false)?;
            let playback = daemon.open_playback(endpoint.clone(), binding)?;
            assert!(!capture.0.shared.armed.load(Ordering::SeqCst));
            assert!(!playback.device.shared.armed.load(Ordering::SeqCst));
            assert!(capture.0.shared.lock()?.queue.is_empty());
            let capture_state = capture.0.shared.clone();
            let playback_state = playback.device.shared.clone();
            let (runtime, _stop, _peer) = approved()?;
            let lease = runtime.lease_control();
            let capture = AudioCaptureController::attach(lease.clone(), capture, binding)?;
            let playback = AudioPlaybackController::attach(lease.clone(), playback, binding)?;
            let pts = sample_flow(&capture, &playback, binding, kind).await?;
            assert_eq!(capture_state.lock()?.graph_rate, Some((1, 48000)));
            if channels == 1 {
                lease.stop(StopReason::Revoked)?;
            } else {
                login.pulse().await?;
                let until = Instant::now() + Duration::from_secs(1);
                while desktop.is_active() && Instant::now() < until {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
                assert!(!desktop.is_active());
            }
            assert!(capture.poll().is_err());
            assert!(playback.play(&tone(binding, pts)).is_err());
            daemon.gone()?;
            assert!(capture_state.lock()?.queue.is_empty());
            assert!(playback_state.lock()?.playing.is_none());
            if channels == 2 {
                assert!(
                    LinuxAudioCapture::open(endpoint, binding).is_err(),
                    "old desktop must not reopen after unlock"
                );
            }
        }
        assert!(!login.locked.load(Ordering::SeqCst));
        login.conn.release_name("org.freedesktop.login1").await?;
        login.conn.close().await?;
    }
    let login = Login::new("wayland").await?;
    let daemon = Daemon::new()?;
    let desktop = Arc::new(LinuxDesktopSession::open_wayland(std::process::id())?);
    let endpoints = LinuxAudioEndpoint::enumerate_at(desktop.clone(), daemon.directory.path())?;
    let endpoint = endpoints
        .into_iter()
        .find(|v| v.name() == "nestlink-selected-sink")
        .ok_or("selected sink absent")?;
    let binding = AudioBinding {
        source: 7,
        channels: 2,
        connection: 9,
    };
    assert!(
        daemon
            .open_capture(endpoint.clone(), binding, true)
            .is_err(),
        "target.object alone cannot authorize a wrong graph link"
    );
    daemon.gone()?;
    let mut capture = daemon.open_capture(endpoint.clone(), binding, false)?;
    let mut remove = daemon.command("pw-cli");
    remove.args(["destroy", &endpoint.node.to_string()]);
    assert!(daemon.run(remove)?.status.success());
    let until = Instant::now() + Duration::from_secs(1);
    while capture.check().is_ok() && Instant::now() < until {
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert!(capture.check().is_err());
    capture.reset()?;
    daemon.gone()?;
    assert!(LinuxAudioCapture::open(endpoint, binding).is_err());
    drop(daemon);

    // A 44.1kHz six-channel driver must convert the fixed 48kHz stereo PCM.
    let daemon = Daemon::with_format(44100, true)?;
    let endpoint = LinuxAudioEndpoint::enumerate_at(desktop.clone(), daemon.directory.path())?
        .into_iter()
        .find(|v| v.name() == "nestlink-selected-sink")
        .ok_or("sink absent")?;
    let capture = daemon.open_capture(endpoint.clone(), binding, false)?;
    let playback = daemon.open_playback(endpoint, binding)?;
    let state = capture.0.shared.clone();
    let (runtime, _stop, _peer) = approved()?;
    let lease = runtime.lease_control();
    let capture = AudioCaptureController::attach(lease.clone(), capture, binding)?;
    let playback = AudioPlaybackController::attach(lease.clone(), playback, binding)?;
    sample_flow(&capture, &playback, binding, "44100Hz six-channel graph").await?;
    assert_eq!(
        state.lock()?.graph_rate,
        Some((1, 44100)),
        "must observe real graph rate, not assume configured rate"
    );
    lease.stop(StopReason::Revoked)?;
    daemon.gone()?;
    drop(daemon);

    for failure in [
        "server-exit",
        "socket-replacement",
        "serial-replacement",
        "link-replacement",
    ] {
        let mut daemon = Daemon::new()?;
        let endpoint = LinuxAudioEndpoint::enumerate_at(desktop.clone(), daemon.directory.path())?
            .into_iter()
            .find(|v| v.name() == "nestlink-selected-sink")
            .ok_or("sink absent")?;
        let capture = daemon.open_capture(endpoint.clone(), binding, false)?;
        let playback = daemon.open_playback(endpoint.clone(), binding)?;
        let capture_state = capture.0.shared.clone();
        let playback_state = playback.device.shared.clone();
        let (runtime, _stop, _peer) = approved()?;
        let lease = runtime.lease_control();
        let capture = AudioCaptureController::attach(lease.clone(), capture, binding)?;
        let playback = AudioPlaybackController::attach(lease.clone(), playback, binding)?;
        sample_flow(&capture, &playback, binding, failure).await?;
        let mut replacement_socket = None;
        match failure {
            "server-exit" => daemon.stop()?,
            "socket-replacement" => {
                fs::rename(
                    daemon.directory.path().join("pipewire-0"),
                    daemon.directory.path().join("original-socket"),
                )?;
                replacement_socket = Some(std::os::unix::net::UnixListener::bind(
                    daemon.directory.path().join("pipewire-0"),
                )?);
            }
            "serial-replacement" => {
                let mut remove = daemon.command("pw-cli");
                remove.args(["destroy", &endpoint.node.to_string()]);
                assert!(daemon.run(remove)?.status.success());
                let mut create = daemon.command("pw-cli");
                create.args(["create-node", "adapter", "{ factory.name = support.null-audio-sink node.name = nestlink-selected-sink media.class = Audio/Sink audio.position = [ FL FR ] object.linger = true adapter.auto-port-config = { mode = dsp monitor = true position = preserve } }"]);
                assert!(daemon.run(create)?.status.success());
                let recreated =
                    LinuxAudioEndpoint::enumerate_at(desktop.clone(), daemon.directory.path())?
                        .into_iter()
                        .find(|v| v.name() == "nestlink-selected-sink")
                        .ok_or("replacement sink absent")?;
                assert_ne!(endpoint.serial, recreated.serial);
                println!(
                    "recreated sink: original node {} serial {}, replacement node {} serial {}",
                    endpoint.node, endpoint.serial, recreated.node, recreated.serial
                );
            }
            "link-replacement" => {
                let mut link = daemon.command("pw-link");
                link.args([
                    "nestlink-other-sink:monitor_FL",
                    "nestlink-system-audio-capture:input_FL",
                ]);
                assert!(daemon.run(link)?.status.success());
            }
            _ => unreachable!(),
        }
        let until = Instant::now() + Duration::from_secs(1);
        while capture_state.check().is_ok() && Instant::now() < until {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert!(capture.poll().is_err(), "old audio survived {failure}");
        assert!(
            playback
                .play(&tone(binding, 100 * CHUNK_FRAMES as u64))
                .is_err()
        );
        assert!(
            lease
                .subscribe_stopped()
                .borrow()
                .as_ref()
                .is_some_and(|report| report.reason == StopReason::PlatformChanged)
        );
        assert!(capture_state.lock()?.queue.is_empty());
        assert!(playback_state.lock()?.playing.is_none());
        assert!(
            LinuxAudioCapture::open(endpoint, binding).is_err(),
            "old endpoint reopened after {failure}"
        );
        if failure == "socket-replacement" {
            drop(replacement_socket);
            fs::remove_file(daemon.directory.path().join("pipewire-0"))?;
            fs::rename(
                daemon.directory.path().join("original-socket"),
                daemon.directory.path().join("pipewire-0"),
            )?;
            assert!(
                capture.poll().is_err(),
                "restored pathname must not restore old authorization"
            );
        }
        if failure != "server-exit" {
            daemon.gone()?;
        }
        println!("{failure}: terminal old stream, shared lease stopped and pending PCM cleared");
    }
    login.conn.close().await?;
    Ok(())
}
