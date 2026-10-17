//! Local render-device adapters for approved media sessions.
//!
//! Device selection is read from this machine's configuration. No endpoint
//! identifier from a peer or browser is accepted by this module.

use nestlink_app_core::{
    CoreHandle, Lifecycle, NativeAudioBinding, NativeAudioError, NativeAudioRole,
};
use nestlink_remote::audio::{
    AudioBinding, AudioCaptureDevice, AudioChunk, AudioDevice, AudioPlaybackDevice, CapturedAudio,
};
use std::io;
use tokio::{sync::watch, task::JoinHandle};

#[cfg(target_os = "linux")]
use nestlink_platform_audio::{LinuxAudioCapture, LinuxAudioEndpoint, LinuxAudioPlayback};
#[cfg(windows)]
use nestlink_platform_audio::{WindowsAudioCapture, WindowsAudioEndpoint, WindowsAudioPlayback};

#[cfg(windows)]
const AUDIO_RENDER_DEVICE_ID: &str = "NESTLINK_AUDIO_RENDER_DEVICE_ID";
#[cfg(target_os = "linux")]
const AUDIO_RENDER_ENDPOINT: &str = "NESTLINK_AUDIO_RENDER_ENDPOINT";

pub(crate) enum SystemAudioCapture {
    #[cfg(windows)]
    Windows(WindowsAudioCapture),
    #[cfg(target_os = "linux")]
    Linux(LinuxAudioCapture),
    #[cfg(not(any(windows, target_os = "linux")))]
    Unsupported,
}

pub(crate) enum SystemAudioPlayback {
    #[cfg(windows)]
    Windows(WindowsAudioPlayback),
    #[cfg(target_os = "linux")]
    Linux(LinuxAudioPlayback),
    #[cfg(not(any(windows, target_os = "linux")))]
    Unsupported,
}

/// Open local system loopback capture for an already checked session binding.
/// Windows uses the OS multimedia default unless a local endpoint ID is
/// configured. Linux requires a local PipeWire endpoint selector (node name or
/// object serial), since PipeWire exposes default routing through session
/// metadata rather than the bounded endpoint inventory API.
pub(crate) fn open_system_capture(binding: AudioBinding) -> io::Result<SystemAudioCapture> {
    binding.validate()?;
    #[cfg(windows)]
    {
        let endpoint = windows_endpoint()?;
        WindowsAudioCapture::open(endpoint, binding).map(SystemAudioCapture::Windows)
    }
    #[cfg(target_os = "linux")]
    {
        let endpoint = linux_endpoint()?;
        LinuxAudioCapture::open(endpoint, binding).map(SystemAudioCapture::Linux)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = binding;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "system audio capture is unavailable on this target",
        ))
    }
}

/// Open local system playback for the same approved session binding.
pub(crate) fn open_system_playback(binding: AudioBinding) -> io::Result<SystemAudioPlayback> {
    binding.validate()?;
    #[cfg(windows)]
    {
        let endpoint = windows_endpoint()?;
        WindowsAudioPlayback::open(endpoint, binding).map(SystemAudioPlayback::Windows)
    }
    #[cfg(target_os = "linux")]
    {
        let endpoint = linux_endpoint()?;
        LinuxAudioPlayback::open(endpoint, binding).map(SystemAudioPlayback::Linux)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = binding;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "system audio playback is unavailable on this target",
        ))
    }
}

impl AudioDevice for SystemAudioCapture {
    fn check(&mut self) -> io::Result<()> {
        match self {
            #[cfg(windows)]
            Self::Windows(device) => AudioDevice::check(device),
            #[cfg(target_os = "linux")]
            Self::Linux(device) => AudioDevice::check(device),
            #[cfg(not(any(windows, target_os = "linux")))]
            Self::Unsupported => Err(unsupported()),
        }
    }

    fn reset(&mut self) -> io::Result<()> {
        match self {
            #[cfg(windows)]
            Self::Windows(device) => AudioDevice::reset(device),
            #[cfg(target_os = "linux")]
            Self::Linux(device) => AudioDevice::reset(device),
            #[cfg(not(any(windows, target_os = "linux")))]
            Self::Unsupported => Ok(()),
        }
    }
}

impl AudioCaptureDevice for SystemAudioCapture {
    fn poll_chunk(&mut self) -> io::Result<Option<CapturedAudio>> {
        match self {
            #[cfg(windows)]
            Self::Windows(device) => AudioCaptureDevice::poll_chunk(device),
            #[cfg(target_os = "linux")]
            Self::Linux(device) => AudioCaptureDevice::poll_chunk(device),
            #[cfg(not(any(windows, target_os = "linux")))]
            Self::Unsupported => Err(unsupported()),
        }
    }
}

impl AudioDevice for SystemAudioPlayback {
    fn check(&mut self) -> io::Result<()> {
        match self {
            #[cfg(windows)]
            Self::Windows(device) => AudioDevice::check(device),
            #[cfg(target_os = "linux")]
            Self::Linux(device) => AudioDevice::check(device),
            #[cfg(not(any(windows, target_os = "linux")))]
            Self::Unsupported => Err(unsupported()),
        }
    }

    fn reset(&mut self) -> io::Result<()> {
        match self {
            #[cfg(windows)]
            Self::Windows(device) => AudioDevice::reset(device),
            #[cfg(target_os = "linux")]
            Self::Linux(device) => AudioDevice::reset(device),
            #[cfg(not(any(windows, target_os = "linux")))]
            Self::Unsupported => Ok(()),
        }
    }
}

impl AudioPlaybackDevice for SystemAudioPlayback {
    fn enqueue(&mut self, chunk: &AudioChunk) -> io::Result<()> {
        match self {
            #[cfg(windows)]
            Self::Windows(device) => AudioPlaybackDevice::enqueue(device, chunk),
            #[cfg(target_os = "linux")]
            Self::Linux(device) => AudioPlaybackDevice::enqueue(device, chunk),
            #[cfg(not(any(windows, target_os = "linux")))]
            Self::Unsupported => Err(unsupported()),
        }
    }
}

#[cfg(windows)]
fn windows_endpoint() -> io::Result<WindowsAudioEndpoint> {
    match std::env::var(AUDIO_RENDER_DEVICE_ID) {
        Ok(device_id) if !device_id.is_empty() => WindowsAudioEndpoint::enumerate()?
            .into_iter()
            .find(|endpoint| endpoint.device_id() == device_id)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "configured Windows render endpoint is not in the local inventory",
                )
            }),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "configured Windows render endpoint ID is empty",
        )),
        Err(std::env::VarError::NotPresent) => WindowsAudioEndpoint::default_render(),
        Err(std::env::VarError::NotUnicode(_)) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "configured Windows render endpoint ID is not valid Unicode",
        )),
    }
}

#[cfg(target_os = "linux")]
fn linux_endpoint() -> io::Result<LinuxAudioEndpoint> {
    use nestlink_platform_session::LinuxDesktopSession;
    use std::sync::Arc;

    let selector = std::env::var(AUDIO_RENDER_ENDPOINT).map_err(|error| match error {
        std::env::VarError::NotPresent => io::Error::new(
            io::ErrorKind::NotFound,
            "set NESTLINK_AUDIO_RENDER_ENDPOINT to a local PipeWire node name or object serial",
        ),
        std::env::VarError::NotUnicode(_) => io::Error::new(
            io::ErrorKind::InvalidInput,
            "configured PipeWire endpoint selector is not valid Unicode",
        ),
    })?;
    if selector.is_empty() || selector.len() > 1024 || selector.chars().any(char::is_control) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "configured PipeWire endpoint selector is invalid",
        ));
    }

    let pid = std::process::id();
    let desktop = if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        Arc::new(LinuxDesktopSession::open_wayland(pid)?)
    } else {
        let display = std::env::var("DISPLAY").map_err(|_| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "a local X11 or Wayland desktop session is required for PipeWire audio",
            )
        })?;
        Arc::new(LinuxDesktopSession::open(pid, &display)?)
    };
    let endpoints = LinuxAudioEndpoint::enumerate(desktop)?;
    let serial = selector.parse::<u64>().ok();
    let mut matches = endpoints.into_iter().filter(|endpoint| {
        endpoint.name() == selector || serial.is_some_and(|value| endpoint.serial() == value)
    });
    let endpoint = matches.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "configured PipeWire render endpoint is not in the local inventory",
        )
    })?;
    if matches.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "configured PipeWire endpoint selector is ambiguous",
        ));
    }
    Ok(endpoint)
}

#[cfg(not(any(windows, target_os = "linux")))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "system audio is unavailable on this target",
    )
}

const NATIVE_AUDIO_SOURCE: u32 = 0;
const NATIVE_AUDIO_CHANNELS: u8 = 2;

enum PreparedAudio {
    Capture(SystemAudioCapture),
    Playback(SystemAudioPlayback),
}

impl PreparedAudio {
    fn reset(mut self) -> io::Result<()> {
        match &mut self {
            Self::Capture(device) => AudioDevice::reset(device),
            Self::Playback(device) => AudioDevice::reset(device),
        }
    }
}

/// Owns the daemon-lifetime local audio actor. It never owns a media sender or
/// receiver; AppCore retains those and exposes only this worker monitor.
pub struct NativeAudioTask {
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<io::Result<()>>>,
}

impl NativeAudioTask {
    pub fn request_stop(&self) {
        self.stop.send_replace(true);
    }

    /// Preserve the join handle when the caller's select is cancelled.
    pub async fn wait(&mut self) -> Result<(), io::Error> {
        let result = match self.task.as_mut() {
            Some(task) => match task.await {
                Ok(result) => result,
                Err(error) => Err(io::Error::other(error)),
            },
            None => return Ok(()),
        };
        self.task.take();
        result
    }

    pub async fn join(mut self) -> Result<(), io::Error> {
        self.wait().await
    }
}

pub fn spawn_native_audio(core: CoreHandle) -> NativeAudioTask {
    let (stop, receiver) = watch::channel(false);
    NativeAudioTask {
        stop,
        task: Some(tokio::spawn(run_native_audio(core, receiver))),
    }
}

async fn run_native_audio(core: CoreHandle, mut stop: watch::Receiver<bool>) -> io::Result<()> {
    let mut observed = core.observe();
    'actor: loop {
        if *stop.borrow() || core.snapshot().lifecycle != Lifecycle::Running {
            return Ok(());
        }
        let Some(binding) = core.native_audio_binding() else {
            tokio::select! {
                changed = observed.changed() => if changed.is_err() { return Ok(()); },
                changed = stop.changed() => if changed.is_err() || *stop.borrow() { return Ok(()); },
            }
            continue 'actor;
        };

        let platform_binding = AudioBinding {
            connection: binding.connection_generation,
            source: NATIVE_AUDIO_SOURCE,
            channels: NATIVE_AUDIO_CHANNELS,
        };
        let role = binding.role;
        let opening = tokio::task::spawn_blocking(move || match role {
            NativeAudioRole::HostCapture => {
                open_system_capture(platform_binding).map(PreparedAudio::Capture)
            }
            NativeAudioRole::ControllerPlayback => {
                open_system_playback(platform_binding).map(PreparedAudio::Playback)
            }
        })
        .await
        .map_err(io::Error::other)?;
        let prepared = match opening {
            Ok(prepared) => prepared,
            Err(_) => {
                fail_if_current(&core, &binding);
                continue 'actor;
            }
        };
        if *stop.borrow() || !is_current(&core, &binding) {
            tokio::task::spawn_blocking(move || prepared.reset())
                .await
                .map_err(io::Error::other)??;
            if *stop.borrow() {
                return Ok(());
            }
            continue 'actor;
        }

        let attach_core = core.clone();
        let attach_binding = binding.clone();
        let attach = tokio::task::spawn_blocking(move || match prepared {
            PreparedAudio::Capture(device) => {
                attach_core.attach_native_audio_capture(&attach_binding, device)
            }
            PreparedAudio::Playback(device) => {
                attach_core.attach_native_audio_playback(&attach_binding, device)
            }
        })
        .await
        .map_err(io::Error::other)?;
        let monitor = match attach {
            Ok(monitor) => monitor,
            Err(error) => {
                fail_if_current(&core, &binding);
                if matches!(&error, NativeAudioError::Cleanup(_)) {
                    return Err(io::Error::other(error));
                }
                continue 'actor;
            }
        };

        loop {
            if *stop.borrow() || core.snapshot().lifecycle != Lifecycle::Running {
                return Ok(());
            }
            if !is_current(&core, &binding) {
                break;
            }
            let status = monitor.status();
            if status.finished {
                fail_if_current(&core, &binding);
                break;
            }
            tokio::select! {
                changed = observed.changed() => if changed.is_err() { return Ok(()); },
                changed = stop.changed() => if changed.is_err() || *stop.borrow() { return Ok(()); },
                _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {},
            }
        }
    }
}

fn is_current(core: &CoreHandle, expected: &NativeAudioBinding) -> bool {
    core.native_audio_binding().as_ref() == Some(expected)
}

fn fail_if_current(core: &CoreHandle, expected: &NativeAudioBinding) {
    if is_current(core, expected) {
        let _ = core.fail_native_audio(expected);
    }
}
