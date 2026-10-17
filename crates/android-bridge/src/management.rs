#![cfg_attr(not(target_os = "android"), allow(dead_code))]

mod browser_data;
mod native_network;
mod services;

use crate::browser_host::{AndroidBrowserHostPort, AndroidBrowserHostProvider};
use crate::file_transfer::{
    AndroidFileIdentity, AndroidFileTransfers, browse_json, export_json, roots_json, task_json,
};
use nestlink_app_core::{
    Action, AppCore, ApprovedServer, BrowserHostStatus, CoreHandle, DisplayDescriptor, Limits,
    NativeAudioBinding, NativeAudioRole, NativeClipboardAction, NativeClipboardBinding,
    NativeClipboardEffect, NativeClipboardEndpoint, NativeClipboardError,
    NativeClipboardPlatformFactory, NativeDisplayRequest, NativeDisplayState, NativeSessionBinding,
    NativeSessionConfig, NativeSessionStatus, NativeVideoBinding, OperationResult, OperationStatus,
    Page, RemoteAccess, ShutdownState,
};
use nestlink_protocol::{
    Path, Permission,
    api::{ApprovalChoice, RemotePasswordSettings, RemoteView, TrustChoice},
};
use nestlink_remote::input::InputLayout;
use nestlink_sdk::{
    DeviceIdentity, NetworkMonitor, PlatformLinkAddress, PlatformNetworkFacts, PlatformRoute,
    browse::NativeBrowseRequest,
};
use serde::Deserialize;
use std::{
    collections::HashSet,
    sync::{Arc, Mutex, MutexGuard, OnceLock},
    time::Duration,
};
use tokio::runtime::{Builder, Runtime};

/// Android's native owner for one app-core instance. The Compose layer only
/// receives results of app-core actions and snapshots; it does not call the
/// management SDK or author server-backed state transitions itself.
pub(crate) struct AndroidManagementSession {
    core: Mutex<Option<AppCore>>,
    handle: CoreHandle,
    network: Arc<NetworkMonitor>,
    /// The management API only exposes lookup by request id. Keep the set of
    /// requests created by this local session here, then re-read every value
    /// through app-core before presenting its current server state.
    remote_request_ids: Mutex<Vec<String>>,
    platform_capture: Mutex<PlatformCaptureStatus>,
    file_transfers: Mutex<AndroidFileTransfers>,
    host_files: Arc<Mutex<crate::host_files::AndroidHostFiles>>,
    browser_data: Arc<crate::browser_data::AndroidBrowserDataRegistry>,
    // Keep the Tokio runtime last so app-core's owner Drop signals shutdown
    // while the runtime is still alive.
    runtime: Runtime,
}

/// Independent optional permissions selected by the user for this request.
#[derive(Clone, Copy, Default)]
pub(crate) struct AndroidPermissionChoices {
    pub input: bool,
    pub audio: bool,
    pub file_read: bool,
    pub file_write: bool,
    pub clipboard_read: bool,
    pub clipboard_write: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AndroidPlatformNetworkSnapshot {
    network_handle: i64,
    interface_name: String,
    link_addresses: Vec<AndroidLinkAddress>,
    routes: Vec<AndroidRoute>,
    dns_servers: Vec<String>,
    has_internet: bool,
    validated: bool,
    not_metered: bool,
    not_restricted: bool,
    transports: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AndroidLinkAddress {
    address: String,
    prefix_length: u8,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AndroidRoute {
    destination: String,
    prefix_length: u8,
    gateway: Option<String>,
}

impl From<AndroidPlatformNetworkSnapshot> for PlatformNetworkFacts {
    fn from(snapshot: AndroidPlatformNetworkSnapshot) -> Self {
        Self {
            network_handle: snapshot.network_handle,
            interface_name: snapshot.interface_name,
            link_addresses: snapshot
                .link_addresses
                .into_iter()
                .map(|address| PlatformLinkAddress {
                    address: address.address,
                    prefix_length: address.prefix_length,
                })
                .collect(),
            routes: snapshot
                .routes
                .into_iter()
                .map(|route| PlatformRoute {
                    destination: route.destination,
                    prefix_length: route.prefix_length,
                    gateway: route.gateway,
                })
                .collect(),
            dns_servers: snapshot.dns_servers,
            has_internet: snapshot.has_internet,
            validated: snapshot.validated,
            not_metered: snapshot.not_metered,
            not_restricted: snapshot.not_restricted,
            transports: snapshot.transports,
        }
    }
}

impl AndroidManagementSession {
    pub(crate) fn new(
        installation: DeviceIdentity,
        browser_host_port: Option<Arc<dyn AndroidBrowserHostPort>>,
    ) -> Result<Self, String> {
        let runtime = Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .thread_name("nestlink-android-core")
            .build()
            .map_err(|_| "Android management runtime could not start".to_owned())?;
        let host_files = Arc::new(Mutex::new(crate::host_files::AndroidHostFiles::default()));
        let browser_data = Arc::new(crate::browser_data::AndroidBrowserDataRegistry::new(
            host_files.clone(),
        ));
        let browser_core = Arc::new(OnceLock::new());
        let core = {
            let _entered = runtime.enter();
            let network = Arc::new(
                NetworkMonitor::start()
                    .map_err(|_| "Android network monitor could not start".to_owned())?,
            );
            let config = NativeSessionConfig::new(Arc::clone(&network));
            let config = match browser_host_port {
                Some(port) => config.with_browser_host(AndroidBrowserHostProvider::config(
                    port,
                    Arc::clone(&browser_data),
                    Arc::clone(&browser_core),
                )),
                None => config,
            };
            let core =
                AppCore::with_identity_and_native_session(Limits::default(), installation, config)
                    .map_err(|_| "Android app-core could not start".to_owned())?;
            (core, network)
        };
        let (core, network) = core;
        let handle = core.handle();
        browser_core
            .set(handle.clone())
            .map_err(|_| "Android BrowserHost app-core handle could not be installed".to_owned())?;
        Ok(Self {
            core: Mutex::new(Some(core)),
            handle,
            network,
            remote_request_ids: Mutex::new(Vec::new()),
            platform_capture: Mutex::new(PlatformCaptureStatus::default()),
            file_transfers: Mutex::new(AndroidFileTransfers::default()),
            host_files,
            browser_data,
            runtime,
        })
    }

    pub(crate) fn verify_server(&self, server: ApprovedServer) -> Result<(), String> {
        let ticket = self
            .handle
            .switch_server(server)
            .map_err(|_| "Android app-core rejected the server configuration".to_owned())?;
        let result = self.wait(ticket)?;
        require_success(&result)?;
        Ok(())
    }

    pub(crate) fn device_id(&self) -> Result<String, String> {
        self.handle
            .snapshot()
            .installation
            .as_ref()
            .map(|installation| installation.device_id.clone())
            .ok_or_else(|| "app-core has no installation identity".to_owned())
    }

    pub(crate) fn login(
        &self,
        username: String,
        password: nestlink_auth::Secret,
        factor: Option<nestlink_auth::Secret>,
    ) -> Result<String, String> {
        let snapshot = self.dispatch(Action::SignIn {
            username,
            password,
            factor,
        })?;
        let principal = snapshot
            .principal
            .as_ref()
            .ok_or_else(|| "app-core did not publish the authenticated account".to_owned())?;
        serde_json::to_string(principal)
            .map_err(|_| "account response could not be encoded".to_owned())
    }

    pub(crate) fn me_json(&self) -> Result<String, String> {
        let snapshot = self.dispatch(Action::Load {
            page: Page::AccountSecurity,
        })?;
        let me = snapshot
            .security
            .data
            .as_ref()
            .ok_or_else(|| "app-core did not publish account security".to_owned())?;
        serde_json::to_string(me.as_ref())
            .map_err(|_| "account response could not be encoded".to_owned())
    }

    pub(crate) fn devices_json(&self) -> Result<String, String> {
        let snapshot = self.dispatch(Action::Load {
            page: Page::Devices,
        })?;
        let devices = snapshot
            .devices
            .data
            .as_ref()
            .ok_or_else(|| "app-core did not publish the device list".to_owned())?;
        serde_json::to_string(devices.as_ref())
            .map_err(|_| "device response could not be encoded".to_owned())
    }

    pub(crate) fn register_controller(&self, name: String) -> Result<(), String> {
        self.dispatch(Action::EnrollLocalDevice {
            name,
            platform: "android".to_owned(),
            capabilities: vec!["controller".to_owned()],
            path_mode: "direct_preferred".to_owned(),
        })?;
        Ok(())
    }

    pub(crate) fn register_host(&self, name: String) -> Result<(), String> {
        self.dispatch(Action::EnrollLocalDevice {
            name,
            platform: "android".to_owned(),
            capabilities: vec!["controller".to_owned(), "host".to_owned()],
            path_mode: "direct_preferred".to_owned(),
        })?;
        Ok(())
    }

    /// Record the Android platform's actual MediaProjection lifecycle. Activation
    /// is accepted only while app-core exposes a connected host View session.
    pub(crate) fn report_platform_capture(
        &self,
        active: bool,
        reason: String,
        session_binding: Option<NativeSessionBinding>,
    ) -> Result<String, String> {
        if active {
            self.require_host_capture_eligible()?;
            if session_binding.as_ref() != self.handle.native_host_session_binding().as_ref() {
                return Err("screen capture requires an active host View session".to_owned());
            }
        } else if let Some(binding) = session_binding.as_ref() {
            self.handle.clear_native_video_stream_for(binding);
        }
        if reason.len() > 96
            || !reason
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            return Err("invalid Android capture lifecycle reason".to_owned());
        }
        let mut status = lock(
            &self.platform_capture,
            "Android screen capture state is unavailable",
        )?;
        if active && status.active {
            return Err("Android screen capture is already active".to_owned());
        }
        status.generation = status.generation.saturating_add(1);
        status.active = active;
        status.binding = active.then_some(session_binding).flatten();
        status.reason = reason;
        serde_json::to_string(&*status)
            .map_err(|_| "Android screen capture state could not be encoded".to_owned())
    }

    pub(crate) fn require_host_capture_eligible(&self) -> Result<(), String> {
        let snapshot = self.handle.snapshot();
        if snapshot.principal.is_none() {
            return Err("screen capture requires an authenticated account".to_owned());
        }
        let device_id = self.device_id()?;
        let host_is_registered = snapshot.devices.data.as_ref().is_some_and(|devices| {
            devices.iter().any(|entry| {
                entry.device.id == device_id
                    && !entry.revoked
                    && entry
                        .device
                        .capabilities
                        .iter()
                        .any(|capability| capability == "host")
            })
        });
        if !host_is_registered {
            return Err("register this installation as a host before screen capture".to_owned());
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn host_view_session_authorized(&self) -> bool {
        self.handle.native_host_session_binding().is_some()
    }

    pub(crate) fn host_session_binding_json(&self) -> Result<Option<String>, String> {
        self.handle
            .native_host_session_binding()
            .map(|binding| {
                serde_json::to_string(&binding)
                    .map_err(|_| "Android host session binding could not be encoded".to_owned())
            })
            .transpose()
    }

    pub(crate) fn host_capture_pts(
        &self,
        binding: &NativeSessionBinding,
        age_ns: u64,
    ) -> Result<u64, String> {
        let status = lock(
            &self.platform_capture,
            "Android capture state is unavailable",
        )?;
        if !status.active || status.binding.as_ref() != Some(binding) || age_ns > 100_000_000 {
            return Err("invalid original projection capture timestamp".into());
        }
        drop(status);
        let at = std::time::Instant::now()
            .checked_sub(Duration::from_nanos(age_ns))
            .ok_or("capture clock underflow")?;
        self.handle
            .native_video_capture_pts(binding, at)
            .map_err(|error| error.to_string())
    }
    pub(crate) fn configure_host_video_stream(
        &self,
        session_binding: &NativeSessionBinding,
        source: u32,
        width: u32,
        height: u32,
        layout_epoch: u64,
    ) -> Result<(), String> {
        let status = lock(
            &self.platform_capture,
            "Android capture state is unavailable",
        )?;
        if !status.active || status.binding.as_ref() != Some(session_binding) || source != 0 {
            return Err(
                "video configuration requires the exact active MediaProjection grant".into(),
            );
        }
        drop(status);
        let display = DisplayDescriptor {
            source,
            left: 0,
            top: 0,
            width,
            height,
            label: "Android shared screen".into(),
        };
        let current = self
            .handle
            .native_displays(session_binding)
            .map_err(|error| error.to_string())?;
        if current.catalog.is_none() {
            if layout_epoch != 1 {
                return Err("initial projection layout epoch must be one".into());
            }
            self.handle
                .publish_native_display_candidates(session_binding, vec![display], true)
                .map_err(|error| error.to_string())?;
            self.runtime
                .block_on(self.handle.configure_native_video_stream(
                    session_binding,
                    source,
                    width,
                    height,
                    layout_epoch,
                ))
                .map_err(|error| error.to_string())
        } else if current
            .selected
            .as_ref()
            .is_some_and(|selected| selected.layout_epoch == layout_epoch)
            && current.displays == vec![display.clone()]
        {
            Ok(())
        } else {
            self.runtime
                .block_on(self.handle.refresh_system_native_display_layout(
                    session_binding,
                    vec![display],
                    layout_epoch,
                ))
                .map_err(|error| error.to_string())
        }
    }

    pub(crate) fn host_display_ready(&self, binding: &NativeSessionBinding) -> Result<u64, String> {
        let status = lock(
            &self.platform_capture,
            "Android capture state is unavailable",
        )?;
        if !status.active || status.binding.as_ref() != Some(binding) {
            return Err("projection grant retired".into());
        }
        drop(status);
        self.runtime
            .block_on(self.handle.advertise_native_displays(binding))
            .map_err(|error| error.to_string())?;
        if let Some(request) = self
            .handle
            .native_display_switch_request(binding)
            .map_err(|error| error.to_string())?
        {
            self.runtime
                .block_on(self.handle.commit_native_display_switch(binding, &request))
                .map_err(|error| error.to_string())?;
        }
        let state = self
            .handle
            .native_displays(binding)
            .map_err(|error| error.to_string())?;
        Ok(if state.pending.is_none() {
            state.selected.map_or(0, |selected| selected.layout_epoch)
        } else {
            0
        })
    }
    fn controller_displays(
        &self,
    ) -> Result<Option<(NativeSessionBinding, NativeDisplayState)>, String> {
        let snapshot = self.handle.snapshot();
        let Some(session) = snapshot.native_session.data.as_ref().filter(|session| {
            session.status == NativeSessionStatus::Connected && !session.host_view_authorized
        }) else {
            return Ok(None);
        };
        let binding = NativeSessionBinding {
            request_id: session.request_id.clone(),
            connection_generation: session.connection_generation,
        };
        let state = self
            .handle
            .native_displays(&binding)
            .map_err(|error| error.to_string())?;
        Ok(Some((binding, state)))
    }
    pub(crate) fn native_displays_json(&self) -> Result<Option<String>, String> {
        self.controller_displays()?
            .map(|(_, state)| {
                serde_json::to_string(&state)
                    .map_err(|_| "display state could not be encoded".into())
            })
            .transpose()
    }
    pub(crate) fn select_remote_display(&self, request_json: &str) -> Result<String, String> {
        if request_json.len() > 4096 {
            return Err("display selection exceeds budget".into());
        }
        let request: NativeDisplayRequest =
            serde_json::from_str(request_json).map_err(|_| "invalid display request".to_owned())?;
        let Some((binding, _)) = self.controller_displays()? else {
            return Err("there is no controller View session".into());
        };
        let state = self
            .runtime
            .block_on(self.handle.select_native_display(&binding, request))
            .map_err(|error| error.to_string())?;
        serde_json::to_string(&state).map_err(|_| "display state could not be encoded".into())
    }
    pub(crate) fn clear_host_video_stream_for(&self, binding: &NativeSessionBinding) {
        self.handle.clear_native_video_stream_for(binding);
    }

    pub(crate) fn remote_video_layout(
        &self,
    ) -> Result<Option<nestlink_app_core::VideoLayout>, String> {
        let Some((_binding, state)) = self.controller_displays()? else {
            return Ok(None);
        };
        if state.pending.is_some() {
            return Ok(None);
        }
        let Some(selection) = state.selected else {
            return Ok(None);
        };
        self.handle
            .native_video_layout(selection.source)
            .map_err(|error| error.to_string())
    }

    pub(crate) fn poll_remote_video(
        &self,
    ) -> Result<Option<nestlink_app_core::DecodedVideo>, String> {
        let Some((binding, state)) = self.controller_displays()? else {
            return Ok(None);
        };
        if state.pending.is_some() {
            return Ok(None);
        }
        let Some(selection) = state.selected else {
            return Ok(None);
        };
        self.handle
            .poll_native_video_for_selection(&binding, &selection)
            .map_err(|error| error.to_string())
    }

    pub(crate) fn send_host_video_frame(
        &self,
        session_binding: &NativeSessionBinding,
        binding: NativeVideoBinding,
        pts_90khz: u64,
        keyframe: bool,
        payload: Vec<u8>,
    ) -> Result<(), String> {
        self.runtime
            .block_on(self.handle.send_native_video_frame(
                session_binding,
                binding,
                pts_90khz,
                keyframe,
                payload,
            ))
            .map_err(|error| error.to_string())
    }

    pub(crate) fn native_video_keyframe_needed(
        &self,
        session_binding: &NativeSessionBinding,
        binding: NativeVideoBinding,
    ) -> Result<bool, String> {
        if self.handle.native_host_session_binding().as_ref() != Some(session_binding) {
            return Err("video feedback requires an active host View session".to_owned());
        }
        self.runtime
            .block_on(
                self.handle
                    .native_video_keyframe_needed(session_binding, binding),
            )
            .map_err(|error| error.to_string())
    }

    pub(crate) fn native_host_input_authorized(&self, binding: &NativeSessionBinding) -> bool {
        self.handle.native_host_input_authorized(binding)
    }

    pub(crate) fn native_audio_binding_json(&self) -> Result<Option<String>, String> {
        self.handle
            .native_audio_binding()
            .map(|binding| {
                let role = match binding.role {
                    NativeAudioRole::HostCapture => "HostCapture",
                    NativeAudioRole::ControllerPlayback => "ControllerPlayback",
                };
                serde_json::to_string(&serde_json::json!({
                    "request_id": binding.request_id,
                    "connection_generation": binding.connection_generation,
                    "role": role,
                }))
                .map_err(|_| "Android audio binding could not be encoded".to_owned())
            })
            .transpose()
    }

    pub(crate) fn attach_native_audio_capture(
        &self,
        binding: &NativeAudioBinding,
        device: crate::platform_audio::AndroidAudioDevice,
    ) -> Result<(), String> {
        let Some(current) = self.handle.native_audio_binding() else {
            return reject_android_audio_device(
                device,
                "there is no authorized Android host Audio session".to_owned(),
            );
        };
        if current != *binding || binding.role != NativeAudioRole::HostCapture {
            return reject_android_audio_device(
                device,
                "Android Audio binding changed before host capture attached".to_owned(),
            );
        }
        self.handle
            .attach_native_audio_capture(binding, device)
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub(crate) fn attach_native_audio_playback(
        &self,
        binding: &NativeAudioBinding,
        device: crate::platform_audio::AndroidAudioDevice,
    ) -> Result<(), String> {
        let Some(current) = self.handle.native_audio_binding() else {
            return reject_android_audio_device(
                device,
                "there is no authorized Android controller Audio session".to_owned(),
            );
        };
        if current != *binding || binding.role != NativeAudioRole::ControllerPlayback {
            return reject_android_audio_device(
                device,
                "Android Audio binding changed before controller playback attached".to_owned(),
            );
        }
        self.handle
            .attach_native_audio_playback(binding, device)
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub(crate) fn native_audio_worker_status_json(
        &self,
        binding: &NativeAudioBinding,
    ) -> Result<Option<String>, String> {
        let Some(status) = self
            .handle
            .native_audio_worker_monitor(binding)
            .map(|monitor| monitor.status())
        else {
            return Ok(None);
        };
        serde_json::to_string(&serde_json::json!({
            "finished": status.finished,
            "cleanup_timed_out": status.cleanup_timed_out,
            "error": status.error,
        }))
        .map(Some)
        .map_err(|_| "Android audio worker status could not be encoded".to_owned())
    }

    pub(crate) fn fail_native_audio(&self, binding: &NativeAudioBinding) -> Result<(), String> {
        self.handle
            .fail_native_audio(binding)
            .map_err(|error| error.to_string())
    }

    pub(crate) fn attach_native_input_device<D: nestlink_remote::input::InputDevice>(
        &self,
        binding: &NativeSessionBinding,
        source: u32,
        layout_epoch: u64,
        device: D,
        layout: InputLayout,
    ) -> Result<(), String> {
        self.runtime
            .block_on(async {
                self.handle
                    .attach_native_input_device(binding, source, layout_epoch, device, layout)
                    .await
            })
            .map_err(|error| error.to_string())
    }

    pub(crate) fn native_input_layout(
        &self,
    ) -> Result<Option<nestlink_app_core::NativeInputLayout>, String> {
        self.handle
            .native_input_layout()
            .map_err(|error| error.to_string())
    }

    pub(crate) fn send_native_input(
        &self,
        binding: &nestlink_app_core::NativeInputBinding,
        action: nestlink_app_core::NativeInputAction,
    ) -> Result<(), String> {
        self.runtime
            .block_on(self.handle.send_native_input(binding, action))
            .map_err(|error| error.to_string())
    }

    pub(crate) fn release_native_input(
        &self,
        binding: &nestlink_app_core::NativeInputBinding,
    ) -> Result<(), String> {
        self.runtime
            .block_on(self.handle.release_native_input(binding))
            .map_err(|error| error.to_string())
    }

    pub(crate) fn report_network_facts(
        &self,
        facts_json: &str,
        observer_active: bool,
        elapsed_realtime_ms: i64,
        uptime_ms: i64,
    ) -> Result<(), String> {
        let clocks = u64::try_from(elapsed_realtime_ms)
            .and_then(|elapsed| u64::try_from(uptime_ms).map(|uptime| (elapsed, uptime)));
        let Ok((elapsed_realtime_ms, uptime_ms)) = clocks else {
            self.network.report_platform_facts(None, false, 0, 0);
            return Err("Android monotonic network clocks are invalid".to_owned());
        };

        if facts_json.len() > 65_536 {
            self.network
                .report_platform_facts(None, false, elapsed_realtime_ms, uptime_ms);
            return Err("Android network facts exceed the size limit".to_owned());
        }
        let facts = if facts_json.is_empty() {
            None
        } else {
            match serde_json::from_str::<AndroidPlatformNetworkSnapshot>(facts_json) {
                Ok(snapshot) => Some(PlatformNetworkFacts::from(snapshot)),
                Err(_) => {
                    self.network
                        .report_platform_facts(None, false, elapsed_realtime_ms, uptime_ms);
                    return Err("Android network facts are invalid".to_owned());
                }
            }
        };
        self.network
            .report_platform_facts(facts, observer_active, elapsed_realtime_ms, uptime_ms);
        Ok(())
    }

    pub(crate) fn platform_capture_json(&self) -> Result<String, String> {
        let status = lock(
            &self.platform_capture,
            "Android screen capture state is unavailable",
        )?;
        serde_json::to_string(&*status)
            .map_err(|_| "Android screen capture state could not be encoded".to_owned())
    }

    pub(crate) fn revoke_device(&self, device_id: String) -> Result<(), String> {
        self.dispatch(Action::RevokeDevice { device_id })?;
        Ok(())
    }

    pub(crate) fn request_view(
        &self,
        host_device_id: String,
        choices: AndroidPermissionChoices,
    ) -> Result<String, String> {
        let AndroidPermissionChoices {
            input: request_input,
            audio: request_audio,
            file_read: request_file_read,
            file_write: request_file_write,
            clipboard_read: request_clipboard_read,
            clipboard_write: request_clipboard_write,
        } = choices;
        if host_device_id == self.device_id()? {
            return Err("this installation cannot request remote access to itself".to_owned());
        }
        let snapshot = self.dispatch(Action::Load {
            page: Page::Devices,
        })?;
        let devices = snapshot
            .devices
            .data
            .as_ref()
            .ok_or_else(|| "app-core did not publish the device list".to_owned())?;
        let host = devices
            .iter()
            .find(|entry| entry.device.id == host_device_id && !entry.revoked)
            .ok_or_else(|| "selected host is not an active registered device".to_owned())?;
        if !host
            .device
            .capabilities
            .iter()
            .any(|capability| capability == "host")
        {
            return Err("selected device has not declared host capability".to_owned());
        }
        let mut permissions = vec![Permission::View as i32];
        if request_input {
            permissions.push(Permission::Input as i32);
        }
        if request_audio {
            permissions.push(Permission::Audio as i32);
        }
        if request_file_read {
            permissions.push(Permission::FileRead as i32);
        }
        if request_file_write {
            permissions.push(Permission::FileWrite as i32);
        }
        if request_clipboard_read {
            permissions.push(Permission::ClipboardRead as i32);
        }
        if request_clipboard_write {
            permissions.push(Permission::ClipboardWrite as i32);
        }
        let snapshot = self.dispatch(Action::RequestRemote {
            host_device_id,
            permissions,
            path_mode: "direct_preferred".to_owned(),
            access: RemoteAccess::LocalApproval,
        })?;
        let request = snapshot
            .selected_request
            .data
            .as_ref()
            .ok_or_else(|| "app-core did not publish the created request".to_owned())?;
        self.remember_remote_request(&request.id)?;
        encode_remote(request.as_ref())
    }

    pub(crate) fn remote_request_json(&self, request_id: String) -> Result<String, String> {
        let snapshot = self.dispatch(Action::InspectRemote { request_id })?;
        let request = snapshot
            .selected_request
            .data
            .as_ref()
            .ok_or_else(|| "app-core did not publish the requested state".to_owned())?;
        encode_remote(request.as_ref())
    }

    pub(crate) fn remote_requests_json(&self) -> Result<String, String> {
        let snapshot = self.dispatch(Action::Load {
            page: Page::Requests,
        })?;
        let mut requests = Vec::<serde_json::Value>::new();
        let mut seen_ids = HashSet::new();
        if let Some(current) = snapshot.requests.data.as_deref() {
            for request in current {
                if seen_ids.insert(request.id.clone()) {
                    requests.push(
                        serde_json::to_value(request)
                            .map_err(|_| "remote request list could not be encoded".to_owned())?,
                    );
                }
            }
        }
        let ids = self
            .remote_request_ids
            .lock()
            .map_err(|_| "Android request list is unavailable".to_owned())?
            .clone();
        for id in ids {
            let snapshot = self.dispatch(Action::InspectRemote {
                request_id: id.clone(),
            })?;
            if let Some(request) = snapshot.selected_request.data.as_deref()
                && seen_ids.insert(request.id.clone())
            {
                requests.push(
                    serde_json::to_value(request)
                        .map_err(|_| "remote request list could not be encoded".to_owned())?,
                );
            }
        }
        serde_json::to_string(&requests)
            .map_err(|_| "remote request list could not be encoded".to_owned())
    }

    pub(crate) fn trusted_devices_json(&self, host_device_id: String) -> Result<String, String> {
        if host_device_id != self.device_id()? {
            return Err("only the local host can read its trusted devices".to_owned());
        }
        let snapshot = self.dispatch(Action::LoadTrustedDevices { host_device_id })?;
        let trusted = snapshot
            .trusted_devices
            .data
            .as_ref()
            .ok_or_else(|| "app-core did not publish the trusted-device list".to_owned())?;
        serde_json::to_string(trusted)
            .map_err(|_| "trusted devices could not be encoded".to_owned())
    }

    pub(crate) fn trust_remote(
        &self,
        request_id: String,
        expected_revision: u64,
        expires_at_unix_ms: u64,
    ) -> Result<String, String> {
        let host_device_id = self.device_id()?;
        let current = self.dispatch(Action::InspectRemote {
            request_id: request_id.clone(),
        })?;
        let request = current
            .selected_request
            .data
            .as_ref()
            .ok_or_else(|| "app-core did not publish the request to trust".to_owned())?;
        if request.host_device_id != host_device_id
            || request.status != "approved"
            || request.lease_sequence == 0
        {
            return Err("trust requires an approved active request for this host".to_owned());
        }

        let current_trust = self.dispatch(Action::LoadTrustedDevices {
            host_device_id: host_device_id.clone(),
        })?;
        let existing_revision = current_trust
            .trusted_devices
            .data
            .as_ref()
            .filter(|trusted| trusted.host_device_id == host_device_id)
            .and_then(|trusted| {
                trusted
                    .devices
                    .iter()
                    .find(|entry| entry.controller_device_id == request.controller_device_id)
            })
            .map_or(0, |entry| entry.revision);
        if existing_revision != expected_revision {
            return Err("trusted-device revision changed; refresh the list".to_owned());
        }

        let snapshot = self.dispatch(Action::TrustRemote {
            request_id,
            choice: TrustChoice {
                expected_revision,
                expires_at_unix_ms,
            },
        })?;
        let trusted =
            snapshot.trusted_devices.data.as_ref().ok_or_else(|| {
                "app-core did not publish the updated trusted-device list".to_owned()
            })?;
        serde_json::to_string(trusted)
            .map_err(|_| "trusted devices could not be encoded".to_owned())
    }

    pub(crate) fn revoke_device_trust(
        &self,
        host_device_id: String,
        controller_device_id: String,
        expected_revision: u64,
    ) -> Result<String, String> {
        if host_device_id != self.device_id()? {
            return Err("only the local host can revoke its trusted devices".to_owned());
        }
        let snapshot = self.dispatch(Action::RevokeDeviceTrust {
            host_device_id,
            controller_device_id,
            expected_revision,
        })?;
        let trusted =
            snapshot.trusted_devices.data.as_ref().ok_or_else(|| {
                "app-core did not publish the updated trusted-device list".to_owned()
            })?;
        serde_json::to_string(trusted)
            .map_err(|_| "trusted devices could not be encoded".to_owned())
    }

    pub(crate) fn remote_password_json(&self, host_device_id: String) -> Result<String, String> {
        if host_device_id != self.device_id()? {
            return Err("only the local host can read its password settings".to_owned());
        }
        let snapshot = self.dispatch(Action::LoadRemotePassword { host_device_id })?;
        let settings =
            snapshot.remote_password.data.as_ref().ok_or_else(|| {
                "app-core did not publish the remote password settings".to_owned()
            })?;
        serde_json::to_string(&settings.settings)
            .map_err(|_| "remote password settings could not be encoded".to_owned())
    }

    pub(crate) fn configure_remote_password(
        &self,
        settings_json: String,
        password: nestlink_auth::Secret,
    ) -> Result<String, String> {
        if settings_json.len() > 4_096 {
            return Err("remote password settings exceed the Android bridge limit".to_owned());
        }
        let settings: RemotePasswordSettings = serde_json::from_str(&settings_json)
            .map_err(|_| "remote password settings are invalid".to_owned())?;
        let snapshot = self.dispatch(Action::ConfigureRemotePassword { settings, password })?;
        let configured = snapshot.remote_password.data.as_ref().ok_or_else(|| {
            "app-core did not publish the configured password settings".to_owned()
        })?;
        serde_json::to_string(&configured.settings)
            .map_err(|_| "remote password settings could not be encoded".to_owned())
    }

    pub(crate) fn revoke_remote_password(&self, expected_revision: u64) -> Result<String, String> {
        let snapshot = self.dispatch(Action::RevokeRemotePassword { expected_revision })?;
        let settings =
            snapshot.remote_password.data.as_ref().ok_or_else(|| {
                "app-core did not publish the revoked password settings".to_owned()
            })?;
        serde_json::to_string(&settings.settings)
            .map_err(|_| "remote password settings could not be encoded".to_owned())
    }

    pub(crate) fn remote_password_offer_json(&self, request_id: String) -> Result<String, String> {
        let current = self.dispatch(Action::InspectRemote {
            request_id: request_id.clone(),
        })?;
        let request = current
            .selected_request
            .data
            .as_ref()
            .ok_or_else(|| "app-core did not publish the password request".to_owned())?;
        if request.controller_device_id != self.device_id()? || request.status != "pending" {
            return Err(
                "password scope is available only to this controller's pending request".to_owned(),
            );
        }
        let snapshot = self.dispatch(Action::LoadRemotePasswordOffer { request_id })?;
        let offer = snapshot
            .remote_password_offer
            .data
            .as_ref()
            .ok_or_else(|| "app-core did not publish the remote password scope".to_owned())?;
        serde_json::to_string(&offer.settings)
            .map_err(|_| "remote password scope could not be encoded".to_owned())
    }

    pub(crate) fn authorize_remote_password(
        &self,
        request_id: String,
        expected_revision: u64,
        password: nestlink_auth::Secret,
    ) -> Result<String, String> {
        let current = self.dispatch(Action::InspectRemote {
            request_id: request_id.clone(),
        })?;
        let request = current
            .selected_request
            .data
            .as_ref()
            .ok_or_else(|| "app-core did not publish the password request".to_owned())?;
        if request.controller_device_id != self.device_id()? || request.status != "pending" {
            return Err(
                "password authorization requires this controller's pending request".to_owned(),
            );
        }
        let snapshot = self.dispatch(Action::AuthorizeRemotePassword {
            request_id,
            expected_revision,
            password,
        })?;
        let request = snapshot.selected_request.data.as_ref().ok_or_else(|| {
            "app-core did not publish the password authorization result".to_owned()
        })?;
        self.remember_remote_request(&request.id)?;
        encode_remote(request.as_ref())
    }

    pub(crate) fn approve_remote(
        &self,
        request_id: String,
        expected_nonce: String,
        expected_policy_revision: u64,
        approved: bool,
        choices: AndroidPermissionChoices,
    ) -> Result<String, String> {
        let AndroidPermissionChoices {
            input: approve_input,
            audio: approve_audio,
            file_read: approve_file_read,
            file_write: approve_file_write,
            clipboard_read: approve_clipboard_read,
            clipboard_write: approve_clipboard_write,
        } = choices;
        let current = self.dispatch(Action::InspectRemote {
            request_id: request_id.clone(),
        })?;
        let request = current
            .selected_request
            .data
            .as_ref()
            .ok_or_else(|| "app-core did not publish the request to review".to_owned())?;
        if request.host_device_id
            != self
                .device_id()
                .map_err(|_| "local host installation is unavailable".to_owned())?
            || request.status != "pending"
            || request.nonce != expected_nonce
            || request.policy_revision != expected_policy_revision
        {
            return Err("request changed before the host decision was submitted".to_owned());
        }
        let paths = if approved {
            if !request.permissions.contains(&(Permission::View as i32))
                || request.paths.is_empty()
                || request
                    .paths
                    .iter()
                    .any(|path| *path != Path::Direct as i32 && *path != Path::Relay as i32)
            {
                return Err("request does not contain an approvable View path".to_owned());
            }
            request.paths.clone()
        } else {
            Vec::new()
        };
        let permissions = if approved {
            if approve_input && !request.permissions.contains(&(Permission::Input as i32)) {
                return Err("request did not ask for Input permission".to_owned());
            }
            if approve_audio && !request.permissions.contains(&(Permission::Audio as i32)) {
                return Err("request did not ask for Audio permission".to_owned());
            }
            if approve_file_read && !request.permissions.contains(&(Permission::FileRead as i32)) {
                return Err("request did not ask for FileRead permission".to_owned());
            }
            if approve_file_write
                && !request
                    .permissions
                    .contains(&(Permission::FileWrite as i32))
            {
                return Err("request did not ask for FileWrite permission".to_owned());
            }
            let mut permissions = vec![Permission::View as i32];
            if approve_input {
                permissions.push(Permission::Input as i32);
            }
            if approve_audio {
                permissions.push(Permission::Audio as i32);
            }
            if approve_file_read {
                permissions.push(Permission::FileRead as i32);
            }
            if approve_file_write {
                permissions.push(Permission::FileWrite as i32);
            }
            if approve_clipboard_read {
                if !request
                    .permissions
                    .contains(&(Permission::ClipboardRead as i32))
                {
                    return Err("request did not ask for ClipboardRead permission".to_owned());
                }
                permissions.push(Permission::ClipboardRead as i32);
            }
            if approve_clipboard_write {
                if !request
                    .permissions
                    .contains(&(Permission::ClipboardWrite as i32))
                {
                    return Err("request did not ask for ClipboardWrite permission".to_owned());
                }
                permissions.push(Permission::ClipboardWrite as i32);
            }
            permissions
        } else {
            Vec::new()
        };
        let snapshot = self.dispatch(Action::ApproveRemote {
            request_id: request_id.clone(),
            expected_nonce,
            expected_policy_revision,
            choice: ApprovalChoice {
                approved,
                permissions,
                paths,
            },
        })?;
        let request = snapshot
            .selected_request
            .data
            .as_ref()
            .ok_or_else(|| "app-core did not publish the approval result".to_owned())?;
        self.remember_remote_request(&request.id)?;
        encode_remote(request.as_ref())
    }

    pub(crate) fn start_native_session(&self, request_id: String) -> Result<String, String> {
        if self
            .handle
            .snapshot()
            .browser_host
            .data
            .as_ref()
            .is_some_and(|host| {
                matches!(
                    host.status,
                    BrowserHostStatus::Establishing
                        | BrowserHostStatus::Connected
                        | BrowserHostStatus::Stopping
                )
            })
        {
            return Err(
                "stop the active BrowserHost owner before starting NativeSession".to_owned(),
            );
        }
        self.dispatch(Action::StartNativeSession { request_id })?;
        self.native_session_json()
    }

    pub(crate) fn stop_native_session(&self, request_id: String) -> Result<String, String> {
        let session = self
            .handle
            .snapshot()
            .native_session
            .data
            .as_ref()
            .cloned()
            .ok_or_else(|| "there is no native session to stop".to_owned())?;
        if session.request_id != request_id
            || !matches!(
                session.status,
                NativeSessionStatus::Establishing | NativeSessionStatus::Connected
            )
        {
            return Err("the selected native session is no longer active".to_owned());
        }
        self.dispatch(Action::StopNativeSession {
            request_id,
            connection_generation: session.connection_generation,
        })?;
        self.native_session_json()
    }

    pub(crate) fn native_session_json(&self) -> Result<String, String> {
        self.handle
            .snapshot()
            .native_session
            .data
            .as_ref()
            .map(|session| serde_json::to_string(session.as_ref()))
            .transpose()
            .map_err(|_| "native session state could not be encoded".to_owned())
            .map(|value| value.unwrap_or_else(|| "null".to_owned()))
    }

    pub(crate) fn start_browser_host(&self, request_id: String) -> Result<String, String> {
        if self
            .handle
            .snapshot()
            .native_session
            .data
            .as_ref()
            .is_some_and(|session| {
                matches!(
                    session.status,
                    NativeSessionStatus::Establishing
                        | NativeSessionStatus::Connected
                        | NativeSessionStatus::Stopping
                )
            })
        {
            return Err(
                "stop the active NativeSession owner before starting BrowserHost".to_owned(),
            );
        }
        self.dispatch(Action::StartBrowserHost { request_id })?;
        self.browser_host_json()
    }

    pub(crate) fn stop_browser_host(&self, request_id: String) -> Result<String, String> {
        let host = self
            .handle
            .snapshot()
            .browser_host
            .data
            .as_ref()
            .cloned()
            .ok_or_else(|| "there is no BrowserHost session to stop".to_owned())?;
        if host.request_id != request_id
            || !matches!(
                host.status,
                BrowserHostStatus::Establishing | BrowserHostStatus::Connected
            )
        {
            return Err("the selected BrowserHost session is no longer active".to_owned());
        }
        self.dispatch(Action::StopBrowserHost {
            request_id,
            connection_generation: host.connection_generation,
        })?;
        self.browser_host_json()
    }

    pub(crate) fn browser_host_json(&self) -> Result<String, String> {
        self.handle
            .snapshot()
            .browser_host
            .data
            .as_ref()
            .map(|host| serde_json::to_string(host.as_ref()))
            .transpose()
            .map_err(|_| "BrowserHost state could not be encoded".to_owned())
            .map(|value| value.unwrap_or_else(|| "null".to_owned()))
    }

    pub(crate) fn native_file_identity_json(&self) -> Result<Option<String>, String> {
        lock(&self.host_files, "Android host file state is unavailable")?.refresh(&self.handle);
        let snapshot = self.handle.snapshot();
        let Some(binding) = self.handle.native_file_session_binding() else {
            return Ok(None);
        };
        let access = self
            .handle
            .native_file_access(&binding, snapshot.generation)
            .map_err(|error| error.to_string())?;
        let identity = AndroidFileIdentity {
            binding,
            core_generation: snapshot.generation,
        };
        lock(
            &self.file_transfers,
            "Android file transfer state is unavailable",
        )?
        .retire_other_sessions(&identity);
        serde_json::to_string(&serde_json::json!({
            "identity": identity,
            "read": access.read,
            "write": access.write,
            "host": access.is_host,
        }))
        .map(Some)
        .map_err(|_| "Android file session identity could not be encoded".to_owned())
    }

    pub(crate) fn set_native_file_download_area(
        &self,
        area: std::path::PathBuf,
    ) -> Result<(), String> {
        lock(
            &self.file_transfers,
            "Android file transfer state is unavailable",
        )?
        .set_download_area(area)
    }

    pub(crate) fn configure_host_file_area(&self, area: std::path::PathBuf) -> Result<(), String> {
        lock(&self.host_files, "Android host file state is unavailable")?.set_area(area)
    }

    pub(crate) fn attach_host_files(&self, identity: &AndroidFileIdentity) -> Result<(), String> {
        lock(&self.host_files, "Android host file state is unavailable")?.attach(
            &self.handle,
            &self.runtime,
            identity,
        )
    }

    pub(crate) fn host_files_json(&self, identity: &AndroidFileIdentity) -> Result<String, String> {
        let value = lock(&self.host_files, "Android host file state is unavailable")?
            .status(&self.handle, identity)?;
        serde_json::to_string(&value)
            .map_err(|_| "Android host files could not be encoded".to_owned())
    }

    pub(crate) fn share_host_file(
        &self,
        identity: &AndroidFileIdentity,
        name: String,
        source: std::fs::File,
    ) -> Result<String, String> {
        lock(&self.host_files, "Android host file state is unavailable")?.share(
            &self.handle,
            identity,
            name,
            source,
        )
    }

    pub(crate) fn approve_host_receive(
        &self,
        identity: &AndroidFileIdentity,
        approved: bool,
    ) -> Result<(), String> {
        lock(&self.host_files, "Android host file state is unavailable")?.approve_receive(
            &self.handle,
            identity,
            approved,
        )
    }

    pub(crate) fn discard_host_file(
        &self,
        identity: &AndroidFileIdentity,
        id: &str,
    ) -> Result<(), String> {
        lock(&self.host_files, "Android host file state is unavailable")?.discard(
            &self.handle,
            identity,
            id,
        )
    }

    pub(crate) fn export_host_file(
        &self,
        identity: &AndroidFileIdentity,
        id: &str,
        destination: std::fs::File,
    ) -> Result<String, String> {
        let status = lock(&self.host_files, "Android host file state is unavailable")?
            .start_export(&self.handle, identity, id, destination)?;
        serde_json::to_string(&export_json(&status))
            .map_err(|_| "Android host file export could not be encoded".to_owned())
    }

    pub(crate) fn cancel_host_export(
        &self,
        identity: &AndroidFileIdentity,
        id: &str,
    ) -> Result<(), String> {
        lock(&self.host_files, "Android host file state is unavailable")?
            .cancel_export(identity, id)
    }

    fn check_file_identity(&self, identity: &AndroidFileIdentity) -> Result<(), String> {
        lock(
            &self.file_transfers,
            "Android file transfer state is unavailable",
        )?
        .check(&self.handle, identity)
    }

    pub(crate) fn native_file_roots_json(
        &self,
        identity: &AndroidFileIdentity,
        write: bool,
    ) -> Result<String, String> {
        self.check_file_identity(identity)?;
        let access = self
            .handle
            .native_file_access(&identity.binding, identity.core_generation)
            .map_err(|error| error.to_string())?;
        if (write && !access.write) || (!write && !access.read) {
            return Err("the current session has no permission for that file direction".to_owned());
        }
        let roots = if write {
            self.runtime.block_on(
                self.handle
                    .native_file_write_roots(&identity.binding, identity.core_generation),
            )
        } else {
            self.runtime.block_on(
                self.handle
                    .native_file_read_roots(&identity.binding, identity.core_generation),
            )
        }
        .map_err(|error| error.to_string())?;
        serde_json::to_string(&roots_json(roots))
            .map_err(|_| "Android file root list could not be encoded".to_owned())
    }

    pub(crate) fn native_file_browse_begin_json(
        &self,
        identity: &AndroidFileIdentity,
        root_id: &str,
        directory: Option<&str>,
    ) -> Result<String, String> {
        self.check_file_identity(identity)?;
        let request = NativeBrowseRequest::new(
            root_id,
            directory,
            nestlink_protocol::DIRECTORY_PAGE_ENTRIES as u32,
        )
        .map_err(|_| "invalid Android remote directory selection".to_owned())?;
        let page = self
            .runtime
            .block_on(self.handle.native_browse_begin(
                &identity.binding,
                identity.core_generation,
                request,
            ))
            .map_err(|error| error.to_string())?;
        serde_json::to_string(&browse_json(page)?)
            .map_err(|_| "Android directory page could not be encoded".to_owned())
    }

    pub(crate) fn native_file_browse_next_json(
        &self,
        identity: &AndroidFileIdentity,
        browse_id: &str,
    ) -> Result<Option<String>, String> {
        self.check_file_identity(identity)?;
        let page = self
            .runtime
            .block_on(self.handle.native_browse_next(
                &identity.binding,
                identity.core_generation,
                browse_id,
                nestlink_protocol::DIRECTORY_PAGE_ENTRIES as u32,
            ))
            .map_err(|error| error.to_string())?;
        page.map(|page| {
            serde_json::to_string(&browse_json(page)?)
                .map_err(|_| "Android directory page could not be encoded".to_owned())
        })
        .transpose()
    }

    pub(crate) fn native_file_browse_cancel(
        &self,
        identity: &AndroidFileIdentity,
        browse_id: &str,
    ) -> Result<(), String> {
        self.check_file_identity(identity)?;
        self.runtime
            .block_on(self.handle.native_browse_cancel(
                &identity.binding,
                identity.core_generation,
                browse_id,
            ))
            .map_err(|error| error.to_string())
    }

    pub(crate) fn native_file_download(
        &self,
        identity: &AndroidFileIdentity,
        root_id: &str,
        relative_path: &str,
    ) -> Result<String, String> {
        let task = lock(
            &self.file_transfers,
            "Android file transfer state is unavailable",
        )?
        .download(&self.handle, identity, root_id, relative_path)?;
        serde_json::to_string(&task_json(&task.status()))
            .map_err(|_| "Android download task could not be encoded".to_owned())
    }

    pub(crate) fn native_file_upload(
        &self,
        identity: &AndroidFileIdentity,
        root_id: &str,
        relative_path: &str,
        display_name: &str,
        source: std::fs::File,
    ) -> Result<String, String> {
        let task = lock(
            &self.file_transfers,
            "Android file transfer state is unavailable",
        )?
        .upload(
            &self.handle,
            identity,
            root_id,
            relative_path,
            display_name,
            source,
        )?;
        serde_json::to_string(&task_json(&task.status()))
            .map_err(|_| "Android upload task could not be encoded".to_owned())
    }

    pub(crate) fn native_file_task_json(
        &self,
        identity: &AndroidFileIdentity,
        task_id: &str,
    ) -> Result<String, String> {
        let status = lock(
            &self.file_transfers,
            "Android file transfer state is unavailable",
        )?
        .task_status(&self.handle, identity, task_id)?;
        serde_json::to_string(&task_json(&status))
            .map_err(|_| "Android file task could not be encoded".to_owned())
    }

    pub(crate) fn native_file_task_control(
        &self,
        identity: &AndroidFileIdentity,
        task_id: &str,
        action: nestlink_app_core::NativeFileTaskAction,
    ) -> Result<(), String> {
        lock(
            &self.file_transfers,
            "Android file transfer state is unavailable",
        )?
        .task_control(&self.handle, identity, task_id, action)
    }

    pub(crate) fn native_file_export(
        &self,
        identity: &AndroidFileIdentity,
        task_id: &str,
        destination: std::fs::File,
    ) -> Result<String, String> {
        let status = lock(
            &self.file_transfers,
            "Android file transfer state is unavailable",
        )?
        .start_export(&self.handle, identity, task_id, destination)?;
        serde_json::to_string(&export_json(&status))
            .map_err(|_| "Android SAF export status could not be encoded".to_owned())
    }

    pub(crate) fn native_file_export_status(
        &self,
        identity: &AndroidFileIdentity,
        export_id: &str,
    ) -> Result<String, String> {
        let status = lock(
            &self.file_transfers,
            "Android file transfer state is unavailable",
        )?
        .export_status(&self.handle, identity, export_id)?;
        serde_json::to_string(&export_json(&status))
            .map_err(|_| "Android SAF export status could not be encoded".to_owned())
    }

    pub(crate) fn native_file_export_cancel(
        &self,
        identity: &AndroidFileIdentity,
        export_id: &str,
    ) -> Result<(), String> {
        lock(
            &self.file_transfers,
            "Android file transfer state is unavailable",
        )?
        .cancel_export(&self.handle, identity, export_id)
    }

    pub(crate) fn native_file_download_discard(
        &self,
        identity: &AndroidFileIdentity,
        task_id: &str,
    ) -> Result<(), String> {
        lock(
            &self.file_transfers,
            "Android file transfer state is unavailable",
        )?
        .discard_download(&self.handle, identity, task_id)
    }

    pub(crate) fn revoke_remote(&self, request_id: String) -> Result<(), String> {
        self.dispatch(Action::RevokeRemote { request_id })?;
        Ok(())
    }

    pub(crate) fn clipboard_status_json(&self) -> Result<Option<String>, String> {
        self.handle
            .native_clipboard_status()
            .map(|status| {
                serde_json::to_string(&status)
                    .map_err(|_| "clipboard_status_unavailable".to_owned())
            })
            .transpose()
    }

    pub(crate) fn clipboard_set_directions(
        &self,
        binding: &NativeClipboardBinding,
        read: bool,
        write: bool,
        factory: Option<Arc<dyn NativeClipboardPlatformFactory>>,
    ) -> Result<String, String> {
        let current = self
            .handle
            .native_clipboard_status()
            .ok_or_else(|| "unauthorized".to_owned())?;
        if current.binding != *binding {
            return Err("stale_binding".to_owned());
        }
        if let Some(factory) = factory {
            if current.ready || (!read && !write) {
                return Err("clipboard_endpoint_already_bound".to_owned());
            }
            self.handle
                .install_native_clipboard_platform_factory(factory)
                .map_err(clipboard_error)?;
        } else if !current.ready && (read || write) {
            return Err("clipboard_platform_required".to_owned());
        }
        let status = self
            .runtime
            .block_on(
                self.handle
                    .set_native_clipboard_directions(binding, read, write),
            )
            .map_err(clipboard_error)?;
        serde_json::to_string(&status).map_err(|_| "clipboard_status_unavailable".to_owned())
    }

    pub(crate) fn clipboard_action(
        &self,
        binding: &NativeClipboardBinding,
        send_local: bool,
    ) -> Result<String, String> {
        let action = if send_local {
            NativeClipboardAction::SendLocalToRemote
        } else {
            NativeClipboardAction::CopyRemoteToLocal
        };
        let effect = self
            .runtime
            .block_on(self.handle.native_clipboard_action(binding, action))
            .map_err(clipboard_error)?;
        Ok(match effect {
            NativeClipboardEffect::Applied => "applied",
            NativeClipboardEffect::NotApplied => "not_applied",
            NativeClipboardEffect::Unknown => "unknown",
        }
        .to_owned())
    }

    /// Observes the exact Core route and its existing local approval. This
    /// reentrant callback cannot install an adapter or approve a direction.
    pub(crate) fn clipboard_platform_allowed(
        &self,
        binding: &NativeClipboardBinding,
        read: bool,
    ) -> bool {
        let Some(status) = self.handle.native_clipboard_status() else {
            return false;
        };
        if status.binding != *binding || !status.ready {
            return false;
        }
        let permitted = match (status.endpoint, read) {
            (NativeClipboardEndpoint::Host, true)
            | (NativeClipboardEndpoint::Controller, false) => status.permitted_read,
            (NativeClipboardEndpoint::Host, false)
            | (NativeClipboardEndpoint::Controller, true) => status.permitted_write,
        };
        permitted
            && if read {
                status.local_read
            } else {
                status.local_write
            }
    }

    pub(crate) fn logout(&self) -> Result<(), String> {
        let ticket = self
            .handle
            .logout()
            .map_err(|_| "Android app-core rejected logout".to_owned())?;
        let result = self.wait(ticket)?;
        require_success(&result)
    }

    pub(crate) fn shutdown(&self) -> Result<(), String> {
        self.browser_data.retire();
        lock(&self.host_files, "Android host file state is unavailable")?.begin_shutdown();
        // Revoke all local owners first, then let Core stop its real services.
        // An empty registry does not prove host filesystem workers have stopped.
        lock(
            &self.file_transfers,
            "Android file transfer state is unavailable",
        )?
        .shutdown_cleanup(&self.handle)?;
        let mut owner = lock(&self.core, "Android app-core owner is unavailable")?;
        if let Some(core) = owner.as_mut() {
            match self
                .runtime
                .block_on(core.shutdown(Duration::from_secs(10)))
            {
                ShutdownState::Complete => {
                    *owner = None;
                }
                ShutdownState::Pending => {
                    return Err("Android app-core cleanup is still running".to_owned());
                }
                ShutdownState::Failed => return Err("Android app-core cleanup failed".to_owned()),
            }
        }
        let files = lock(
            &self.file_transfers,
            "Android file transfer state is unavailable",
        )?
        .shutdown_cleanup(&self.handle)?;
        let hosts = lock(&self.host_files, "Android host file state is unavailable")?
            .cleanup_complete(&self.handle);
        if !files || !hosts {
            return Err("Android file owners or private cleanup are still retained; retry closing the same native handle".into());
        }
        Ok(())
    }

    fn dispatch(
        &self,
        action: Action,
    ) -> Result<std::sync::Arc<nestlink_app_core::Snapshot>, String> {
        let ticket = self
            .handle
            .submit(action)
            .map_err(|_| "Android app-core rejected the management action".to_owned())?;
        let result = self.wait(ticket)?;
        require_success(&result)?;
        Ok(self.handle.snapshot())
    }

    fn wait(&self, ticket: nestlink_app_core::Ticket) -> Result<OperationResult, String> {
        let completion = self
            .runtime
            .block_on(ticket.wait())
            .map_err(|_| "Android app-core ended before completing the action".to_owned())?;
        Ok(completion.result)
    }

    fn remember_remote_request(&self, request_id: &str) -> Result<(), String> {
        let mut ids = lock(
            &self.remote_request_ids,
            "Android request list is unavailable",
        )?;
        ids.retain(|id| id != request_id);
        ids.push(request_id.to_owned());
        if ids.len() > 256 {
            ids.remove(0);
        }
        Ok(())
    }
}

fn reject_android_audio_device(
    mut device: crate::platform_audio::AndroidAudioDevice,
    primary: String,
) -> Result<(), String> {
    use nestlink_remote::audio::AudioDevice;
    match device.reset() {
        Ok(()) => Err(primary),
        Err(cleanup) => Err(format!(
            "{primary}; Android audio cleanup failed: {cleanup}"
        )),
    }
}

fn clipboard_error(error: NativeClipboardError) -> String {
    match error {
        NativeClipboardError::StaleBinding => "stale_binding",
        NativeClipboardError::Unauthorized => "unauthorized",
        NativeClipboardError::LocalConsentRequired => "local_consent_required",
        NativeClipboardError::ReestablishSession => "session_restart_required",
        NativeClipboardError::PlatformUnavailable(_) => "platform_unavailable",
        NativeClipboardError::Transport => "transport_failed",
        NativeClipboardError::Stopped => "owner_stopped",
        NativeClipboardError::Cleanup => "cleanup_unconfirmed",
    }
    .to_owned()
}

#[derive(serde::Serialize, Default)]
struct PlatformCaptureStatus {
    active: bool,
    binding: Option<NativeSessionBinding>,
    generation: u64,
    reason: String,
}

fn lock<'a, T>(mutex: &'a Mutex<T>, message: &str) -> Result<MutexGuard<'a, T>, String> {
    mutex.lock().map_err(|_| message.to_owned())
}

fn require_success(result: &OperationResult) -> Result<(), String> {
    if result.status == OperationStatus::Succeeded {
        return Ok(());
    }
    let failure = result
        .failure
        .as_ref()
        .and_then(|value| serde_json::to_string(value).ok())
        .unwrap_or_else(|| "{}".to_owned());
    Err(format!(
        "app-core {:?} operation {:?}: {failure}",
        result.kind, result.status
    ))
}

fn encode_remote(request: &RemoteView) -> Result<String, String> {
    serde_json::to_string(request)
        .map_err(|_| "remote request response could not be encoded".to_owned())
}

#[cfg(test)]
mod tests {
    use super::{AndroidManagementSession, AndroidPlatformNetworkSnapshot};
    use nestlink_app_core::{Action, Authentication, Page};
    use nestlink_identity::InstallationIdentity;
    use nestlink_sdk::{DeviceIdentity, PlatformNetworkFacts};

    #[test]
    fn connectivity_json_keeps_network_addresses_routes_dns_and_capabilities() {
        let snapshot = serde_json::from_str::<AndroidPlatformNetworkSnapshot>(
            r#"{
                "network_handle": 17,
                "interface_name": "wlan0",
                "link_addresses": [{"address": "192.168.1.20", "prefix_length": 24}],
                "routes": [{"destination": "0.0.0.0", "prefix_length": 0, "gateway": "192.168.1.1"}],
                "dns_servers": ["192.168.1.1"],
                "has_internet": true,
                "validated": true,
                "not_metered": true,
                "not_restricted": true,
                "transports": ["wifi"]
            }"#,
        )
        .unwrap_or_else(|error| panic!("ConnectivityManager fact JSON should parse: {error}"));
        let facts = PlatformNetworkFacts::from(snapshot);

        assert_eq!(facts.network_handle, 17);
        assert_eq!(facts.interface_name, "wlan0");
        assert_eq!(facts.link_addresses[0].address, "192.168.1.20");
        assert_eq!(facts.routes[0].gateway.as_deref(), Some("192.168.1.1"));
        assert_eq!(facts.dns_servers, vec!["192.168.1.1".to_owned()]);
        assert!(facts.has_internet && facts.validated && facts.not_restricted);
        assert_eq!(facts.transports, vec!["wifi".to_owned()]);
    }

    fn disconnected_session() -> AndroidManagementSession {
        AndroidManagementSession::new(
            DeviceIdentity {
                device_id: "4e48e00e-5a88-4cf4-a873-28f393199244".to_owned(),
                identity: InstallationIdentity::from_seed([0x31; 32]),
            },
            None,
        )
        .unwrap_or_else(|error| panic!("session should start: {error}"))
    }

    #[test]
    fn app_core_is_the_source_of_android_installation_and_authentication_state() {
        let session = disconnected_session();
        let snapshot = session.handle.snapshot();

        assert_eq!(
            session.device_id().as_deref(),
            Ok("4e48e00e-5a88-4cf4-a873-28f393199244")
        );
        assert_eq!(snapshot.authentication, Authentication::Disconnected);
        assert_eq!(
            snapshot
                .installation
                .as_ref()
                .map(|installation| installation.device_id.as_str()),
            Some("4e48e00e-5a88-4cf4-a873-28f393199244"),
        );
        assert!(snapshot.principal.is_none());
        assert!(session.shutdown().is_ok());
    }

    #[test]
    fn platform_capture_facts_fail_closed_before_login_and_round_trip_after_stop() {
        let session = disconnected_session();
        assert!(!session.host_view_session_authorized());
        assert!(session.require_host_capture_eligible().is_err());
        assert!(
            session
                .report_platform_capture(true, "projection_active".to_owned(), None)
                .is_err()
        );
        let status: serde_json::Value = serde_json::from_str(
            &session
                .report_platform_capture(false, "local_stop".to_owned(), None)
                .unwrap_or_else(|error| panic!("capture stop fact should be recorded: {error}")),
        )
        .unwrap_or_else(|error| panic!("capture status should be valid JSON: {error}"));
        assert_eq!(status["active"], false);
        assert_eq!(status["generation"], 1);
        assert_eq!(status["reason"], "local_stop");
        assert!(
            session
                .report_platform_capture(false, "contains spaces".to_owned(), None)
                .is_err()
        );
        assert!(session.shutdown().is_ok());
    }

    #[test]
    fn android_management_actions_fail_closed_before_server_verification() {
        let session = disconnected_session();

        let error = session
            .dispatch(Action::Load {
                page: Page::Devices,
            })
            .err();

        assert!(error.is_some());
        let snapshot = session.handle.snapshot();
        assert_eq!(snapshot.authentication, Authentication::Disconnected);
        assert!(snapshot.devices.data.is_none());
        assert!(session.shutdown().is_ok());
    }

    #[test]
    fn android_does_not_invent_remote_requests_before_the_user_creates_one() {
        let session = disconnected_session();

        assert!(matches!(
            session.remote_requests_json(),
            Err(error) if error.contains("\"kind\":\"sign_in_required\"")
        ));
        assert!(
            session
                .remote_request_ids
                .lock()
                .is_ok_and(|requests| requests.is_empty())
        );
        let snapshot = session.handle.snapshot();
        assert!(snapshot.requests.data.is_none());
        assert!(snapshot.selected_request.data.is_none());
        assert!(session.shutdown().is_ok());
    }

    #[test]
    fn installation_seed_buffer_is_zeroized_before_the_app_core_takes_ownership() {
        let mut seed = [0x5a; 32];
        let _identity = InstallationIdentity::from_seed_zeroizing(&mut seed);

        assert!(seed.iter().all(|byte| *byte == 0));
    }
}
