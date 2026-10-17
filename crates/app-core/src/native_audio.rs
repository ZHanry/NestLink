//! Product-owned audio pipelines for proved native sessions.
//!
//! The daemon opens only local platform devices. This module owns the media
//! worker, channel claim, and cleanup receipt for the lifetime of the session.
use super::{CoreHandle, NativeSessionKey, NativeSessionStatus, Shared};
use nestlink_media_session::{
    AudioReceiver, AudioSender, AudioStream, SessionMediaTiming, ShutdownReport, WorkerMonitor,
};
use nestlink_remote::{
    ChannelReceiver, ChannelRuntime, ChannelSender, LeaseControl, RemoteError,
    audio::{AudioBinding, AudioCaptureDevice, AudioPlaybackDevice},
};
use nestlink_session::StopReason;
use nestlink_transport_stream::Channel;
use std::{
    io,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
};

const SOURCE: u32 = 0;
const CHANNELS: u8 = 2;
const BITRATE: u32 = 96_000;

#[derive(Debug, thiserror::Error)]
pub enum NativeAudioError {
    #[error("no matching proved Audio session is authorized")]
    Unauthorized,
    #[error("authorized Audio transport stopped")]
    Transport,
    #[error("platform audio cleanup failed: {0}")]
    Cleanup(#[source] io::Error),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeAudioBinding {
    pub request_id: String,
    pub connection_generation: u64,
    pub role: NativeAudioRole,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeAudioRole {
    HostCapture,
    ControllerPlayback,
}

enum NativeAudioPipeline {
    Capture(AudioSender),
    Playback(AudioReceiver),
}

impl NativeAudioPipeline {
    fn monitor(&self) -> WorkerMonitor {
        match self {
            Self::Capture(sender) => sender.monitor(),
            Self::Playback(receiver) => receiver.monitor(),
        }
    }

    fn shutdown(&mut self, reason: StopReason) -> io::Result<ShutdownReport> {
        match self {
            Self::Capture(sender) => sender.shutdown(reason),
            Self::Playback(receiver) => receiver.shutdown(reason),
        }
    }

    fn reap_finished(&mut self) -> io::Result<bool> {
        match self {
            Self::Capture(sender) => sender.reap_finished(),
            Self::Playback(receiver) => receiver.reap_finished(),
        }
    }
}

pub(super) struct NativeAudioRoute {
    timing: SessionMediaTiming,
    request_id: String,
    connection_generation: u64,
    generation: u64,
    is_host: bool,
    active: AtomicBool,
    lease: LeaseControl,
    shared: Weak<Shared>,
    cleanup_failed: AtomicBool,
    sender: Option<ChannelSender>,
    receiver: Mutex<Option<ChannelReceiver>>,
    attach_lock: Mutex<()>,
    pipeline: Mutex<Option<NativeAudioPipeline>>,
    shutdown: tokio::sync::Mutex<NativeAudioShutdownState>,
}

#[derive(Default)]
struct NativeAudioShutdownState {
    task: Option<tokio::task::JoinHandle<NativeAudioShutdown>>,
    outcome: Option<NativeAudioShutdown>,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct NativeAudioShutdown {
    pub cleanup_failed: bool,
    pub worker_failed: bool,
    pub owner_pending: bool,
}

impl NativeAudioRoute {
    pub(super) fn attach(
        shared: &Arc<Shared>,
        channels: &mut ChannelRuntime,
        key: &NativeSessionKey,
        generation: u64,
        timing: SessionMediaTiming,
    ) -> Result<Arc<Self>, RemoteError> {
        if !key.audio_authorized {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "native session has no Audio permission",
            )
            .into());
        }
        let lease = channels.lease_control();
        lease.check_media_binding(Channel::Audio, key.connection_generation)?;
        let sender = key.is_host.then(|| channels.sender());
        let receiver = if key.is_host {
            None
        } else {
            Some(channels.claim_channel(Channel::Audio)?)
        };
        Ok(Arc::new(Self {
            timing,
            request_id: key.request_id.clone(),
            connection_generation: key.connection_generation,
            generation,
            is_host: key.is_host,
            active: AtomicBool::new(true),
            lease,
            shared: Arc::downgrade(shared),
            cleanup_failed: AtomicBool::new(false),
            sender,
            receiver: Mutex::new(receiver),
            attach_lock: Mutex::new(()),
            pipeline: Mutex::new(None),
            shutdown: tokio::sync::Mutex::new(NativeAudioShutdownState::default()),
        }))
    }

    fn binding(&self) -> AudioBinding {
        AudioBinding {
            connection: self.connection_generation,
            source: SOURCE,
            channels: CHANNELS,
        }
    }

    fn stream(&self) -> AudioStream {
        AudioStream {
            binding: self.binding(),
            bitrate: BITRATE,
        }
    }

    fn check(&self) -> Result<(), NativeAudioError> {
        if !self.active.load(Ordering::Acquire) {
            return Err(NativeAudioError::Unauthorized);
        }
        self.lease
            .check_media_binding(Channel::Audio, self.connection_generation)
            .map_err(|_| NativeAudioError::Unauthorized)
    }

    pub(super) fn binding_view(&self) -> Result<NativeAudioBinding, NativeAudioError> {
        self.check()?;
        Ok(NativeAudioBinding {
            request_id: self.request_id.clone(),
            connection_generation: self.connection_generation,
            role: self.role(),
        })
    }

    fn role(&self) -> NativeAudioRole {
        if self.is_host {
            NativeAudioRole::HostCapture
        } else {
            NativeAudioRole::ControllerPlayback
        }
    }

    fn matches_binding(&self, binding: &NativeAudioBinding) -> bool {
        self.request_id == binding.request_id
            && self.connection_generation == binding.connection_generation
            && self.role() == binding.role
    }

    pub(super) fn worker_monitor(&self) -> Option<WorkerMonitor> {
        self.pipeline
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(NativeAudioPipeline::monitor)
    }

    pub(super) fn retire(&self) {
        self.active.store(false, Ordering::Release);
    }

    pub(super) fn fail(&self) {
        self.retire();
        let _ = self.lease.stop(StopReason::PlatformChanged);
    }

    pub(super) fn attach_capture<D: AudioCaptureDevice>(
        &self,
        device: D,
    ) -> Result<WorkerMonitor, NativeAudioError> {
        if !self.is_host {
            return Err(self.reject_device(device, NativeAudioError::Unauthorized));
        }
        let _attach = match self.attach_lock.lock() {
            Ok(guard) => guard,
            Err(_) => return Err(self.reject_device(device, NativeAudioError::Transport)),
        };
        if let Err(error) = self.check() {
            return Err(self.reject_device(device, error));
        }
        let mut pipeline = match self.pipeline.lock() {
            Ok(pipeline) => pipeline,
            Err(_) => return Err(self.reject_device(device, NativeAudioError::Transport)),
        };
        if pipeline.is_some() {
            return Err(self.reject_device(device, NativeAudioError::Unauthorized));
        }
        let Some(sender) = self.sender.clone() else {
            return Err(self.reject_device(device, NativeAudioError::Unauthorized));
        };
        let sender = match AudioSender::attach_channel_timed(
            sender,
            device,
            self.stream(),
            self.timing.capture.clone(),
        ) {
            Ok(sender) => sender,
            Err(error) => return Err(self.record_cleanup_failure(map_attach_error(error))),
        };
        let monitor = sender.monitor();
        *pipeline = Some(NativeAudioPipeline::Capture(sender));
        Ok(monitor)
    }

    pub(super) fn attach_playback<D: AudioPlaybackDevice>(
        &self,
        device: D,
    ) -> Result<WorkerMonitor, NativeAudioError> {
        if self.is_host {
            return Err(self.reject_device(device, NativeAudioError::Unauthorized));
        }
        let _attach = match self.attach_lock.lock() {
            Ok(guard) => guard,
            Err(_) => return Err(self.reject_device(device, NativeAudioError::Transport)),
        };
        if let Err(error) = self.check() {
            return Err(self.reject_device(device, error));
        }
        let mut pipeline = match self.pipeline.lock() {
            Ok(pipeline) => pipeline,
            Err(_) => return Err(self.reject_device(device, NativeAudioError::Transport)),
        };
        if pipeline.is_some() {
            return Err(self.reject_device(device, NativeAudioError::Unauthorized));
        }
        let receiver = match self.receiver.lock() {
            Ok(mut receiver) => receiver.take(),
            Err(_) => return Err(self.reject_device(device, NativeAudioError::Transport)),
        };
        let Some(receiver) = receiver else {
            return Err(self.reject_device(device, NativeAudioError::Unauthorized));
        };
        let receiver = match AudioReceiver::attach_channel_timed(
            receiver,
            device,
            self.stream(),
            self.timing.playout.clone(),
        ) {
            Ok(receiver) => receiver,
            Err(error) => return Err(self.record_cleanup_failure(map_attach_error(error))),
        };
        let monitor = receiver.monitor();
        *pipeline = Some(NativeAudioPipeline::Playback(receiver));
        Ok(monitor)
    }

    /// Revoke the route immediately, then let the session owner join the actual
    /// media worker off the Tokio executor after the transport stop receipt.
    pub(super) async fn shutdown(self: &Arc<Self>, reason: StopReason) -> NativeAudioShutdown {
        self.retire();
        let mut shutdown = self.shutdown.lock().await;
        if let Some(outcome) = shutdown.outcome {
            return outcome;
        }
        if shutdown.task.is_none() {
            let pipeline = self
                .pipeline
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            self.receiver
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some(mut pipeline) = pipeline {
                let route = self.clone();
                shutdown.task = Some(tokio::task::spawn_blocking(move || {
                    let monitor = pipeline.monitor();
                    let result = catch_unwind(AssertUnwindSafe(|| pipeline.shutdown(reason)))
                        .unwrap_or_else(|_| {
                            Err(io::Error::other("audio worker shutdown panicked"))
                        });
                    // `finished` is published by the worker just before its
                    // thread returns. Only consuming a finished JoinHandle
                    // proves that the thread and its device owner are gone.
                    let reaped = pipeline.reap_finished();
                    let status = monitor.status();
                    let cleanup_failed = !matches!(result, Ok(ShutdownReport::Joined))
                        || status.cleanup_timed_out
                        || !status.finished
                        || reaped.is_err()
                        || route.cleanup_failed.load(Ordering::Acquire);
                    let owner_pending = matches!(reaped, Ok(false));
                    if owner_pending {
                        {
                            *route
                                .pipeline
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                                Some(pipeline);
                        }
                        if let Some(shared) = route.shared.upgrade() {
                            shared.retain_native_audio_owner(route.clone());
                        }
                    }
                    NativeAudioShutdown {
                        cleanup_failed,
                        worker_failed: status.error.is_some(),
                        owner_pending,
                    }
                }));
            } else {
                shutdown.outcome = Some(NativeAudioShutdown {
                    cleanup_failed: self.cleanup_failed.load(Ordering::Acquire),
                    ..NativeAudioShutdown::default()
                });
                return shutdown.outcome.unwrap_or_default();
            }
        }
        let outcome = match shutdown.task.as_mut() {
            Some(task) => match task.await {
                Ok(outcome) => outcome,
                Err(_) => NativeAudioShutdown {
                    cleanup_failed: true,
                    worker_failed: true,
                    owner_pending: self.has_pending_owner(),
                },
            },
            None => NativeAudioShutdown {
                cleanup_failed: true,
                worker_failed: true,
                owner_pending: self.has_pending_owner(),
            },
        };
        shutdown.task.take();
        shutdown.outcome = Some(outcome);
        outcome
    }

    pub(super) fn has_pending_owner(&self) -> bool {
        self.pipeline
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
    }

    pub(super) fn reap_finished_owner(&self) {
        let mut pipeline = self
            .pipeline
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if pipeline
            .as_mut()
            .is_some_and(|owner| owner.reap_finished().unwrap_or(false))
        {
            pipeline.take();
        }
    }

    fn reject_device<D: nestlink_remote::audio::AudioDevice>(
        &self,
        device: D,
        primary: NativeAudioError,
    ) -> NativeAudioError {
        self.record_cleanup_failure(reject_device(device, primary))
    }

    fn record_cleanup_failure(&self, error: NativeAudioError) -> NativeAudioError {
        if matches!(&error, NativeAudioError::Cleanup(_)) {
            self.cleanup_failed.store(true, Ordering::Release);
        }
        error
    }
}

fn reject_device<D: nestlink_remote::audio::AudioDevice>(
    mut device: D,
    primary: NativeAudioError,
) -> NativeAudioError {
    let cleanup = catch_unwind(AssertUnwindSafe(|| device.reset()))
        .unwrap_or_else(|_| Err(io::Error::other("audio device cleanup panicked")));
    match cleanup {
        Ok(()) => primary,
        Err(cleanup) => NativeAudioError::Cleanup(io::Error::new(
            cleanup.kind(),
            format!("audio attachment failed ({primary}); device cleanup failed: {cleanup}"),
        )),
    }
}

fn map_attach_error(error: io::Error) -> NativeAudioError {
    if let Some(RemoteError::Cleanup(cleanup)) = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<RemoteError>())
    {
        return NativeAudioError::Cleanup(io::Error::new(cleanup.kind(), cleanup.to_string()));
    }
    if error.kind() == io::ErrorKind::PermissionDenied {
        NativeAudioError::Unauthorized
    } else {
        NativeAudioError::Transport
    }
}

impl Shared {
    pub(super) fn set_native_audio_route(&self, route: Option<Arc<NativeAudioRoute>>) {
        let previous = {
            let mut current = self
                .native_audio
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::replace(&mut *current, route)
        };
        if let Some(previous) = previous {
            previous.retire();
        }
        self.reap_native_audio_owners();
    }

    pub(super) fn retain_native_audio_owner(&self, route: Arc<NativeAudioRoute>) {
        route.reap_finished_owner();
        if !route.has_pending_owner() {
            return;
        }
        let mut owners = self
            .native_audio_owners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        owners.retain(|owner| {
            owner.reap_finished_owner();
            owner.has_pending_owner()
        });
        if !owners.iter().any(|owner| Arc::ptr_eq(owner, &route)) {
            owners.push(route);
        }
    }

    pub(super) fn reap_native_audio_owners(&self) {
        self.native_audio_owners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|owner| {
                owner.reap_finished_owner();
                owner.has_pending_owner()
            });
    }

    pub(super) fn native_audio_cleanup_pending(&self) -> bool {
        self.reap_native_audio_owners();
        !self
            .native_audio_owners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
    }
}

impl CoreHandle {
    fn reject_native_audio_device<D: nestlink_remote::audio::AudioDevice>(
        &self,
        binding: &NativeAudioBinding,
        device: D,
        primary: NativeAudioError,
    ) -> NativeAudioError {
        let route = self
            .shared
            .native_audio
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .filter(|route| route.matches_binding(binding))
            .cloned();
        match route {
            Some(route) => route.reject_device(device, primary),
            None => reject_device(device, primary),
        }
    }

    fn audio_route(&self) -> Result<Arc<NativeAudioRoute>, NativeAudioError> {
        if self.shared.closing.load(Ordering::Acquire) {
            return Err(NativeAudioError::Unauthorized);
        }
        let snapshot = self.snapshot();
        let session = snapshot
            .native_session
            .data
            .as_ref()
            .filter(|session| session.status == NativeSessionStatus::Connected)
            .ok_or(NativeAudioError::Unauthorized)?;
        let route = self
            .shared
            .native_audio
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .filter(|route| {
                route.request_id == session.request_id
                    && route.connection_generation == session.connection_generation
                    && route.generation == snapshot.generation
                    && route.generation == self.shared.generation.load(Ordering::Acquire)
            })
            .cloned()
            .ok_or(NativeAudioError::Unauthorized)?;
        route.check()?;
        Ok(route)
    }

    fn audio_route_for_binding(
        &self,
        binding: &NativeAudioBinding,
    ) -> Result<Arc<NativeAudioRoute>, NativeAudioError> {
        let route = self.audio_route()?;
        if route.matches_binding(binding) {
            Ok(route)
        } else {
            Err(NativeAudioError::Unauthorized)
        }
    }

    /// Current Audio role for the connected proved session. The actor uses
    /// this identity to open a local device only after AppCore authorizes it.
    pub fn native_audio_binding(&self) -> Option<NativeAudioBinding> {
        self.audio_route().ok()?.binding_view().ok()
    }

    pub fn native_audio_worker_monitor(
        &self,
        binding: &NativeAudioBinding,
    ) -> Option<WorkerMonitor> {
        self.audio_route_for_binding(binding).ok()?.worker_monitor()
    }

    pub fn fail_native_audio(&self, binding: &NativeAudioBinding) -> Result<(), NativeAudioError> {
        let route = self.audio_route_for_binding(binding)?;
        route.fail();
        Ok(())
    }

    pub fn clear_native_audio_route(&self) {
        self.shared.set_native_audio_route(None);
    }

    pub fn attach_native_audio_capture<D: AudioCaptureDevice>(
        &self,
        binding: &NativeAudioBinding,
        device: D,
    ) -> Result<WorkerMonitor, NativeAudioError> {
        let route = match self.audio_route_for_binding(binding) {
            Ok(route) => route,
            Err(error) => {
                return Err(self.reject_native_audio_device(binding, device, error));
            }
        };
        route.attach_capture(device)
    }

    pub fn attach_native_audio_playback<D: AudioPlaybackDevice>(
        &self,
        binding: &NativeAudioBinding,
        device: D,
    ) -> Result<WorkerMonitor, NativeAudioError> {
        let route = match self.audio_route_for_binding(binding) {
            Ok(route) => route,
            Err(error) => {
                return Err(self.reject_native_audio_device(binding, device, error));
            }
        };
        route.attach_playback(device)
    }
}

impl Drop for NativeAudioRoute {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
        let _ = self.lease.stop_if_running(StopReason::ExplicitExit);
    }
}
