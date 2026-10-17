//! Raw Android MediaProjection adapter for the proved BrowserHost WebRTC lease.
//!
//! The Android implementation of the proved BrowserHost MediaProjection port.
//! It deliberately does not encode VP8 or call a NativeSession video route:
//! WebRtcHostPeer owns encoding and transmission after this source yields raw BGRA.

use crate::browser_host::{
    AndroidBrowserCaptureOwners, AndroidBrowserCaptureReservation, AndroidBrowserHostPort, Prepared,
};
use jni::{
    JavaVM,
    objects::{GlobalRef, JByteArray, JClass, JObject, JValue},
};
use nestlink_app_core::{BrowserHostBinding, BrowserHostError};
use nestlink_identity::VerifiedPermit;
use nestlink_protocol::Permission;
use nestlink_remote::{
    audio::{AudioCaptureDevice, AudioChunk, AudioDevice, CHUNK_FRAMES, CapturedAudio},
    input::{Button, InputAction, InputDevice, InputLayout, PlatformInput},
    video::{CaptureDevice, Display, RAW_FRAME_AGE, RawFrame},
};
use nestlink_transport_stream::Channel;
use std::{
    collections::HashMap,
    io,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::watch;
use zeroize::{Zeroize, Zeroizing};

/// Keeps accepted pixels zeroizing until all JNI cleanup/binding checks pass.
struct PendingRawFrame(Option<RawFrame>);

impl Drop for PendingRawFrame {
    fn drop(&mut self) {
        if let Some(frame) = &mut self.0 {
            frame.pixels.zeroize();
        }
    }
}

const FRAME_BYTES: usize = 64 * 1024 * 1024;
const AUDIO_CHANNELS: u8 = 2;
const AUDIO_PACKET_BYTES: usize = 16 + CHUNK_FRAMES * AUDIO_CHANNELS as usize * 2;

struct ActivationLeaseEntry {
    id: u64,
    lease: nestlink_remote::LeaseControl,
    binding: BrowserHostBinding,
    audio: bool,
    input: bool,
}

static ACTIVATION_LEASES: OnceLock<Mutex<HashMap<String, ActivationLeaseEntry>>> = OnceLock::new();
static NEXT_ACTIVATION_LEASE_ID: AtomicU64 = AtomicU64::new(1);

fn activation_leases() -> &'static Mutex<HashMap<String, ActivationLeaseEntry>> {
    ACTIVATION_LEASES.get_or_init(|| Mutex::new(HashMap::new()))
}

struct ActivationLeaseRegistration {
    binding_json: String,
    id: u64,
}

impl ActivationLeaseRegistration {
    fn register(
        lease: nestlink_remote::LeaseControl,
        binding: &BrowserHostBinding,
        binding_json: &str,
        audio: bool,
        input: bool,
    ) -> io::Result<Self> {
        let id = NEXT_ACTIVATION_LEASE_ID.fetch_add(1, Ordering::Relaxed);
        if id == 0 {
            return Err(io::Error::other(
                "BrowserHost activation lease identifier exhausted",
            ));
        }
        let mut registry = activation_leases().lock().map_err(|_| {
            io::Error::other("BrowserHost activation lease registry is unavailable")
        })?;
        if registry.contains_key(binding_json) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "BrowserHost activation binding is already registered",
            ));
        }
        registry.insert(
            binding_json.to_owned(),
            ActivationLeaseEntry {
                id,
                lease,
                binding: binding.clone(),
                audio,
                input,
            },
        );
        Ok(Self {
            binding_json: binding_json.to_owned(),
            id,
        })
    }
}

impl Drop for ActivationLeaseRegistration {
    fn drop(&mut self) {
        let Ok(mut registry) = activation_leases().lock() else {
            return;
        };
        if registry
            .get(&self.binding_json)
            .is_some_and(|entry| entry.id == self.id)
        {
            registry.remove(&self.binding_json);
        }
    }
}

/// Called by the Android capture worker immediately before each platform
/// activation stage. This checks the actual LeaseControl retained for the exact
/// binding; Android snapshot state is not an authorization source.
pub(crate) fn browser_host_activation_lease_active(binding_json: &str) -> bool {
    if binding_json.len() > 8 * 1024 {
        return false;
    }
    let Ok(binding) = serde_json::from_str::<BrowserHostBinding>(binding_json) else {
        return false;
    };
    if binding.request_id.is_empty()
        || binding.connection_generation == 0
        || serde_json::to_string(&binding).ok().as_deref() != Some(binding_json)
    {
        return false;
    }
    let entry = {
        let Ok(registry) = activation_leases().lock() else {
            return false;
        };
        let Some(entry) = registry.get(binding_json) else {
            return false;
        };
        if entry.binding != binding {
            return false;
        }
        (entry.lease.clone(), entry.audio, entry.input)
    };
    let (lease, audio, input) = entry;
    lease
        .check_media_binding(Channel::Video, binding.connection_generation)
        .is_ok()
        && (!audio
            || lease
                .check_media_binding(Channel::Audio, binding.connection_generation)
                .is_ok())
        && (!input
            || lease
                .check_channel_binding(Channel::Input, binding.connection_generation)
                .is_ok())
}

/// JNI port for the ActivityResult/foreground-service capture coordinator.
/// It queues a consent challenge using the complete serialized BrowserHost
/// binding, then polls for a staged one-use grant. No Projection API is called
/// by this preparation phase.
pub(crate) struct JniAndroidBrowserHostPort {
    vm: Arc<JavaVM>,
    coordinator_class: GlobalRef,
}

impl JniAndroidBrowserHostPort {
    /// Resolve and retain the app class while running inside the Java-to-native
    /// call made by NativeSdk. Later BrowserHost work runs on Rust worker
    /// threads, where JNI FindClass would use the system class loader.
    pub(crate) fn from_env(env: &mut jni::JNIEnv<'_>) -> io::Result<Self> {
        let vm = env
            .get_java_vm()
            .map(Arc::new)
            .map_err(|_| io::Error::other("BrowserHost JavaVM is unavailable"))?;
        let coordinator = env
            .find_class("com/zhanry/nestlink/BrowserHostCaptureCoordinator")
            .map_err(|_| io::Error::other("BrowserHost app class could not be resolved"))?;
        let coordinator_class = env
            .new_global_ref(coordinator)
            .map_err(|_| io::Error::other("BrowserHost app class could not be retained"))?;
        Ok(Self {
            vm,
            coordinator_class,
        })
    }

    fn with_env<T>(
        &self,
        operation: impl FnOnce(&mut jni::JNIEnv<'_>) -> jni::errors::Result<T>,
    ) -> io::Result<T> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|_| io::Error::other("BrowserHost coordinator JVM attachment failed"))?;
        let result = env.with_local_frame(16, operation);
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
        }
        result.map_err(|_| io::Error::other("BrowserHost consent coordinator failed"))
    }

    fn request_consent(&self, binding_json: &str) -> io::Result<bool> {
        self.with_env(|env| {
            let binding = JObject::from(env.new_string(binding_json)?);
            let coordinator_class = <&JClass<'_>>::from(self.coordinator_class.as_obj());
            env.call_static_method(
                coordinator_class,
                "requestConsent",
                "(Ljava/lang/String;)Z",
                &[JValue::Object(&binding)],
            )?
            .z()
        })
    }

    fn consent_state(&self, binding_json: &str) -> io::Result<String> {
        self.with_env(|env| {
            let binding = JObject::from(env.new_string(binding_json)?);
            let coordinator_class = <&JClass<'_>>::from(self.coordinator_class.as_obj());
            let value = env
                .call_static_method(
                    coordinator_class,
                    "consentState",
                    "(Ljava/lang/String;)Ljava/lang/String;",
                    &[JValue::Object(&binding)],
                )?
                .l()?;
            let value = jni::objects::JString::from(value);
            env.get_string(&value).map(|value| value.into())
        })
    }

    fn take_endpoint(&self, binding_json: &str) -> io::Result<Option<GlobalRef>> {
        self.with_env(|env| {
            let binding = JObject::from(env.new_string(binding_json)?);
            let coordinator_class = <&JClass<'_>>::from(self.coordinator_class.as_obj());
            let endpoint = env
                .call_static_method(
                    coordinator_class,
                    "takeEndpoint",
                    "(Ljava/lang/String;)Lcom/zhanry/nestlink/AndroidBrowserRawCaptureEndpoint;",
                    &[JValue::Object(&binding)],
                )?
                .l()?;
            if endpoint.is_null() {
                Ok(None)
            } else {
                env.new_global_ref(endpoint).map(Some)
            }
        })
    }

    fn cancel_consent(&self, binding_json: &str) {
        let _ = self.with_env(|env| {
            let binding = JObject::from(env.new_string(binding_json)?);
            let coordinator_class = <&JClass<'_>>::from(self.coordinator_class.as_obj());
            env.call_static_method(
                coordinator_class,
                "cancelConsent",
                "(Ljava/lang/String;)Z",
                &[JValue::Object(&binding)],
            )?
            .z()?;
            Ok(())
        });
    }
}

/// Synchronously retires a pending consent request on every exit path. Rust
/// cancellation can drop `prepare_capture` without polling its select branch,
/// so cleanup cannot live only inside that branch.
struct PendingBrowserHostConsent<'a> {
    port: &'a JniAndroidBrowserHostPort,
    binding_json: &'a str,
    armed: bool,
}

impl<'a> PendingBrowserHostConsent<'a> {
    fn new(port: &'a JniAndroidBrowserHostPort, binding_json: &'a str) -> Self {
        Self {
            port,
            binding_json,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PendingBrowserHostConsent<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.port.cancel_consent(self.binding_json);
        }
    }
}

impl AndroidBrowserHostPort for JniAndroidBrowserHostPort {
    fn supports_audio(&self) -> bool {
        // Android playback capture is available on API 29+, while the app's
        // minSdk is 30. RECORD_AUDIO remains a separate runtime gate checked
        // only if the proved permit grants Audio.
        true
    }

    fn supports_input(&self) -> bool {
        self.with_env(|env| {
            let coordinator_class = <&JClass<'_>>::from(self.coordinator_class.as_obj());
            env.call_static_method(coordinator_class, "supportsInput", "()Z", &[])?
                .z()
        })
        .unwrap_or(false)
    }

    fn prepare_capture(
        &self,
        binding: BrowserHostBinding,
        mut cancel: watch::Receiver<bool>,
    ) -> Prepared<Box<dyn AndroidBrowserCaptureReservation>> {
        let port = Self {
            vm: Arc::clone(&self.vm),
            coordinator_class: self.coordinator_class.clone(),
        };
        Box::pin(async move {
            let binding_json =
                serde_json::to_string(&binding).map_err(|_| BrowserHostError::Capture)?;
            // Arm first: even a JNI exception can arrive after the Java
            // coordinator accepted the pending consent request.
            let mut pending_consent = PendingBrowserHostConsent::new(&port, &binding_json);
            if !port
                .request_consent(&binding_json)
                .map_err(|_| BrowserHostError::Capture)?
            {
                return Err(BrowserHostError::Capture);
            }
            loop {
                if *cancel.borrow() {
                    return Err(BrowserHostError::Cancelled);
                }
                match port
                    .consent_state(&binding_json)
                    .map_err(|_| BrowserHostError::Capture)?
                    .as_str()
                {
                    "denied" => return Err(BrowserHostError::Cancelled),
                    "cancelled" => return Err(BrowserHostError::Cancelled),
                    "granted" => {
                        if let Some(endpoint) = port
                            .take_endpoint(&binding_json)
                            .map_err(|_| BrowserHostError::Capture)?
                        {
                            pending_consent.disarm();
                            drop(pending_consent);
                            return Ok(Box::new(JniAndroidBrowserCaptureReservation {
                                vm: Arc::clone(&port.vm),
                                endpoint,
                                binding_json,
                                binding,
                                activated: false,
                            })
                                as Box<dyn AndroidBrowserCaptureReservation>);
                        }
                    }
                    "pending" => {}
                    _ => return Err(BrowserHostError::Capture),
                }
                tokio::select! {
                    biased;
                    _ = async {
                        loop {
                            if *cancel.borrow() || cancel.changed().await.is_err() { break; }
                        }
                    } => {
                        return Err(BrowserHostError::Cancelled);
                    }
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {}
                }
            }
        })
    }
}

struct JniAndroidBrowserCaptureReservation {
    vm: Arc<JavaVM>,
    endpoint: GlobalRef,
    binding_json: String,
    binding: BrowserHostBinding,
    activated: bool,
}

impl AndroidBrowserCaptureReservation for JniAndroidBrowserCaptureReservation {
    fn prepared_display(&self) -> Result<Display, BrowserHostError> {
        let (width, height) = with_endpoint_env(
            &self.vm,
            "BrowserHost prepared display dimensions are unavailable",
            |env| {
                let binding = JObject::from(env.new_string(&self.binding_json)?);
                let args = &[JValue::Object(&binding)];
                let width = env
                    .call_method(
                        self.endpoint.as_obj(),
                        "preparedDisplayWidth",
                        "(Ljava/lang/String;)I",
                        args,
                    )?
                    .i()?;
                let height = env
                    .call_method(
                        self.endpoint.as_obj(),
                        "preparedDisplayHeight",
                        "(Ljava/lang/String;)I",
                        args,
                    )?
                    .i()?;
                Ok((width, height))
            },
        )
        .map_err(|_| BrowserHostError::Capture)?;
        if !(1..=8192).contains(&width) || !(1..=8192).contains(&height) {
            return Err(BrowserHostError::Capture);
        }
        Ok(Display {
            source: 0,
            logical: InputLayout {
                left: 0,
                top: 0,
                width: width as u32,
                height: height as u32,
            },
        })
    }

    fn activate_after_proof(
        mut self: Box<Self>,
        lease: nestlink_remote::LeaseControl,
        binding: &BrowserHostBinding,
        permit: &VerifiedPermit,
    ) -> Result<AndroidBrowserCaptureOwners, nestlink_sdk::webrtc_host::WebRtcHostError> {
        use nestlink_sdk::webrtc_host::WebRtcHostError;

        if binding != &self.binding
            || serde_json::to_string(binding).ok().as_deref() != Some(&self.binding_json)
            || permit.digest() != binding.permit_sha256
        {
            return Err(WebRtcHostError::Permit);
        }
        let permissions = permit.claims().permissions.as_slice();
        let audio_allowed = permissions.contains(&(Permission::Audio as i32));
        let input_allowed = permissions.contains(&(Permission::Input as i32));
        // Recheck each requested channel immediately before the first Android
        // system call can create a projection, virtual display, or AudioRecord.
        lease
            .check_media_binding(Channel::Video, binding.connection_generation)
            .map_err(|_| WebRtcHostError::Permit)?;
        if audio_allowed {
            lease
                .check_media_binding(Channel::Audio, binding.connection_generation)
                .map_err(|_| WebRtcHostError::Permit)?;
        }
        if input_allowed {
            lease
                .check_channel_binding(Channel::Input, binding.connection_generation)
                .map_err(|_| WebRtcHostError::Permit)?;
        }
        // Retain the real lease before crossing JNI. The Android capture worker
        // may execute this activation after its Handler queue delay, so it must
        // be able to recheck the same live lease immediately before each system
        // resource is created.
        let activation_lease = ActivationLeaseRegistration::register(
            lease.clone(),
            binding,
            &self.binding_json,
            audio_allowed,
            input_allowed,
        )
        .map_err(WebRtcHostError::Io)?;
        let binding_json = self.binding_json.clone();
        let activated = call_endpoint_bool(
            &self.vm,
            &self.endpoint,
            "activateAfterProof",
            "(Ljava/lang/String;ZZ)Z",
            &binding_json,
            &[audio_allowed, input_allowed],
        )
        .map_err(WebRtcHostError::Io)?;
        if !activated {
            return Err(WebRtcHostError::Permit);
        }
        let (width, height) =
            endpoint_dimensions(&self.vm, &self.endpoint).map_err(WebRtcHostError::Io)?;
        if !(1..=8192).contains(&width) || !(1..=8192).contains(&height) {
            return Err(WebRtcHostError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "BrowserHost projection dimensions are invalid",
            )));
        }
        let logical = InputLayout {
            left: 0,
            top: 0,
            width: width as u32,
            height: height as u32,
        };
        let video = Box::new(AndroidBrowserCaptureDevice::new(
            Arc::clone(&self.vm),
            self.endpoint.clone(),
            self.binding_json.clone(),
            activation_lease,
        )?) as Box<dyn CaptureDevice>;
        let audio = if audio_allowed {
            let audio_endpoint =
                endpoint_audio_endpoint(&self.vm, &self.endpoint, &self.binding_json)
                    .map_err(WebRtcHostError::Io)?
                    .ok_or(WebRtcHostError::Permit)?;
            Some(Box::new(AndroidBrowserAudioCaptureDevice::new(
                Arc::clone(&self.vm),
                audio_endpoint,
                self.binding_json.clone(),
            )?) as Box<dyn AudioCaptureDevice>)
        } else {
            None
        };
        let input = if input_allowed {
            Some(Box::new(AndroidBrowserInputDevice::new(
                Arc::clone(&self.vm),
                self.endpoint.clone(),
                self.binding_json.clone(),
            )?) as Box<dyn InputDevice>)
        } else {
            None
        };
        self.activated = true;
        Ok(AndroidBrowserCaptureOwners {
            display: Display { source: 0, logical },
            video,
            audio,
            input,
        })
    }
}

fn endpoint_audio_endpoint(
    vm: &JavaVM,
    endpoint: &GlobalRef,
    binding_json: &str,
) -> io::Result<Option<GlobalRef>> {
    with_endpoint_env(
        vm,
        "BrowserHost AudioRecord owner could not be opened",
        |env| {
            let binding = JObject::from(env.new_string(binding_json)?);
            let object = env
                .call_method(
                    endpoint.as_obj(),
                    "openAudioCapture",
                    "(Ljava/lang/String;)Lcom/zhanry/nestlink/BrowserHostAudioCaptureEndpoint;",
                    &[JValue::Object(&binding)],
                )?
                .l()?;
            if object.is_null() {
                Ok(None)
            } else {
                env.new_global_ref(object).map(Some)
            }
        },
    )
}

impl Drop for JniAndroidBrowserCaptureReservation {
    fn drop(&mut self) {
        if !self.activated {
            let _ = call_endpoint_bool(
                &self.vm,
                &self.endpoint,
                "stopAndAwait",
                "(Ljava/lang/String;)Z",
                &self.binding_json,
                &[],
            );
        }
    }
}

fn call_endpoint_bool(
    vm: &JavaVM,
    endpoint: &GlobalRef,
    method: &str,
    signature: &str,
    binding_json: &str,
    booleans: &[bool],
) -> io::Result<bool> {
    with_endpoint_env(vm, "BrowserHost endpoint rejected the operation", |env| {
        let binding = JObject::from(env.new_string(binding_json)?);
        let mut args = vec![JValue::Object(&binding)];
        let values = booleans
            .iter()
            .copied()
            .map(|enabled| JValue::Bool(u8::from(enabled)))
            .collect::<Vec<_>>();
        args.extend(values.iter().copied());
        env.call_method(endpoint.as_obj(), method, signature, &args)?
            .z()
    })
}

fn endpoint_dimensions(vm: &JavaVM, endpoint: &GlobalRef) -> io::Result<(i32, i32)> {
    with_endpoint_env(
        vm,
        "BrowserHost display dimensions are unavailable",
        |env| {
            let width = env
                .call_method(endpoint.as_obj(), "displayWidth", "()I", &[])?
                .i()?;
            let height = env
                .call_method(endpoint.as_obj(), "displayHeight", "()I", &[])?
                .i()?;
            Ok((width, height))
        },
    )
}

/// Runs a short endpoint JNI operation inside its own local frame and clears
/// any Java exception before returning. Capture teardown may call
/// `stopAndAwait` from Drop after an earlier operation failed, so a pending
/// exception must never leak across this JNI boundary.
fn with_endpoint_env<T>(
    vm: &JavaVM,
    error: &'static str,
    operation: impl FnOnce(&mut jni::JNIEnv<'_>) -> jni::errors::Result<T>,
) -> io::Result<T> {
    let mut env = vm
        .attach_current_thread()
        .map_err(|_| io::Error::other("BrowserHost endpoint JVM attachment failed"))?;
    let result = env.with_local_frame(24, operation);
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_clear();
    }
    result.map_err(|_| io::Error::other(error))
}

/// The activated source may be rejected before VideoController registers its
/// cleanup callback. Retain a drop owner for that interval as well as normal
/// resets. Authorization is retired before crossing into Android cleanup, and
/// an unconfirmed stop remains retryable without restoring authorization.
struct CaptureOwnerCleanup<L> {
    activation_lease: Option<L>,
    stop_owner: Box<dyn FnMut() -> io::Result<()> + Send>,
    complete: bool,
}

impl<L> CaptureOwnerCleanup<L> {
    fn new(
        activation_lease: L,
        stop_owner: impl FnMut() -> io::Result<()> + Send + 'static,
    ) -> Self {
        Self {
            activation_lease: Some(activation_lease),
            stop_owner: Box::new(stop_owner),
            complete: false,
        }
    }

    fn reset(&mut self) -> io::Result<()> {
        // Drop the registration even if JNI or the service's cleanup fails.
        // A late Android callback must never keep capturing on a retired owner.
        self.activation_lease.take();
        if self.complete {
            return Ok(());
        }
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (self.stop_owner)()))
            .unwrap_or_else(|_| {
                Err(io::Error::other(
                    "BrowserHost capture owner cleanup panicked",
                ))
            })?;
        self.complete = true;
        Ok(())
    }
}

impl<L> Drop for CaptureOwnerCleanup<L> {
    fn drop(&mut self) {
        let _ = self.reset();
    }
}

pub(crate) struct AndroidBrowserCaptureDevice {
    vm: Arc<JavaVM>,
    endpoint: GlobalRef,
    binding_json: String,
    cleanup: CaptureOwnerCleanup<ActivationLeaseRegistration>,
}

impl AndroidBrowserCaptureDevice {
    fn new(
        vm: Arc<JavaVM>,
        endpoint: GlobalRef,
        binding_json: String,
        activation_lease: ActivationLeaseRegistration,
    ) -> io::Result<Self> {
        if binding_json.is_empty() || binding_json.len() > 8 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "BrowserHost capture binding is invalid",
            ));
        }
        let cleanup_vm = Arc::clone(&vm);
        let cleanup_endpoint = endpoint.clone();
        let cleanup_binding = binding_json.clone();
        let cleanup = CaptureOwnerCleanup::new(activation_lease, move || {
            let stopped = call_endpoint_bool(
                &cleanup_vm,
                &cleanup_endpoint,
                "stopAndAwait",
                "(Ljava/lang/String;)Z",
                &cleanup_binding,
                &[],
            )?;
            if stopped {
                Ok(())
            } else {
                Err(io::Error::other(
                    "BrowserHost MediaProjection cleanup is not confirmed",
                ))
            }
        });
        Ok(Self {
            vm,
            endpoint,
            binding_json,
            cleanup,
        })
    }

    fn with_env<T>(
        &self,
        operation: impl FnOnce(&mut jni::JNIEnv<'_>) -> jni::errors::Result<T>,
    ) -> io::Result<T> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|_| io::Error::other("BrowserHost capture JVM attachment failed"))?;
        let result = env.with_local_frame(24, operation);
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
        }
        result.map_err(|_| io::Error::other("BrowserHost capture endpoint failed"))
    }

    fn check_binding(&self, env: &mut jni::JNIEnv<'_>) -> jni::errors::Result<bool> {
        let binding = env.new_string(&self.binding_json)?;
        let binding = JObject::from(binding);
        env.call_method(
            self.endpoint.as_obj(),
            "matchesBinding",
            "(Ljava/lang/String;)Z",
            &[JValue::Object(&binding)],
        )?
        .z()
    }
}

impl CaptureDevice for AndroidBrowserCaptureDevice {
    fn check(&mut self) -> io::Result<()> {
        self.with_env(|env| {
            if !self.check_binding(env)? {
                return Ok(false);
            }
            env.call_method(self.endpoint.as_obj(), "isActive", "()Z", &[])?
                .z()
        })?
        .then_some(())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "BrowserHost capture binding is stopped or stale",
            )
        })
    }

    fn poll_frame(&mut self) -> io::Result<Option<RawFrame>> {
        let binding_json = self.binding_json.clone();
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|_| io::Error::other("BrowserHost capture JVM attachment failed"))?;
        let result = env.with_local_frame(24, |env| -> jni::errors::Result<_> {
            Ok((|| -> io::Result<Option<RawFrame>> {
                let matches = self
                    .check_binding(env)
                    .map_err(|_| io::Error::other("BrowserHost capture binding check failed"))?;
                let active = env
                    .call_method(self.endpoint.as_obj(), "isActive", "()Z", &[])
                    .and_then(|value| value.z())
                    .map_err(|_| io::Error::other("BrowserHost capture endpoint is unavailable"))?;
                if !matches || !active {
                    return Ok(None);
                }
                let frame = env
                    .call_method(
                        self.endpoint.as_obj(),
                        "pollRawFrame",
                        "()Lcom/zhanry/nestlink/AndroidBrowserRawFrame;",
                        &[],
                    )
                    .and_then(|value| value.l())
                    .map_err(|_| io::Error::other("BrowserHost raw frame queue failed"))?;
                if frame.is_null() {
                    return Ok(None);
                }

                let frame_result = (|| -> io::Result<Option<RawFrame>> {
                    let width = env
                        .call_method(&frame, "width", "()I", &[])
                        .and_then(|value| value.i())
                        .map_err(|_| io::Error::other("BrowserHost frame width is unavailable"))?;
                    let height = env
                        .call_method(&frame, "height", "()I", &[])
                        .and_then(|value| value.i())
                        .map_err(|_| io::Error::other("BrowserHost frame height is unavailable"))?;
                    let capture_nanos = env
                        .call_method(&frame, "timestampNanos", "()J", &[])
                        .and_then(|value| value.j())
                        .map_err(|_| {
                            io::Error::other("BrowserHost frame timestamp is unavailable")
                        })?;
                    if !(1..=8192).contains(&width) || !(1..=8192).contains(&height) {
                        return Ok(None);
                    }
                    let now = env
                        .call_static_method("java/lang/System", "nanoTime", "()J", &[])
                        .and_then(|value| value.j())
                        .map_err(|_| io::Error::other("Android monotonic clock unavailable"))?;
                    let Some(age) = now
                        .checked_sub(capture_nanos)
                        .filter(|age| *age >= 0)
                        .filter(|age| {
                            u64::try_from(*age)
                                .ok()
                                .is_some_and(|age| age <= RAW_FRAME_AGE.as_nanos() as u64)
                        })
                    else {
                        return Ok(None);
                    };
                    let Some(captured_at) =
                        Instant::now().checked_sub(Duration::from_nanos(age as u64))
                    else {
                        return Ok(None);
                    };
                    let byte_len = (width as usize)
                        .checked_mul(height as usize)
                        .and_then(|pixels| pixels.checked_mul(4));
                    if byte_len.is_none_or(|bytes| bytes == 0 || bytes > FRAME_BYTES) {
                        return Ok(None);
                    }

                    let packed = env
                        .call_method(&frame, "copyPixels", "()[B", &[])
                        .and_then(|value| value.l())
                        .map_err(|_| {
                            io::Error::other("BrowserHost frame pixels could not be copied")
                        })?;
                    let packed = JByteArray::from(packed);
                    let packed_len = match env.get_array_length(&packed) {
                        Ok(length) => length as usize,
                        Err(_) => {
                            if env.exception_check().unwrap_or(false) {
                                let _ = env.exception_clear();
                            }
                            let clear_error = zero_byte_array(env, &packed).err();
                            return Err(clear_error.unwrap_or_else(|| {
                                io::Error::other("BrowserHost pixel buffer length is unavailable")
                            }));
                        }
                    };
                    if packed_len != byte_len.unwrap_or_default() {
                        zero_byte_array(env, &packed)?;
                        return Ok(None);
                    }

                    // Own the native duplicate with zeroizing drop before trying
                    // any JNI cleanup that can fail.
                    let copied = env.convert_byte_array(&packed);
                    if env.exception_check().unwrap_or(false) {
                        let _ = env.exception_clear();
                    }
                    let pixels = copied.map(Zeroizing::new);
                    let cleared = zero_byte_array(env, &packed);
                    let mut pixels = pixels.map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "BrowserHost pixel conversion failed",
                        )
                    })?;
                    cleared?;
                    if pixels.len() != byte_len.unwrap_or_default() {
                        return Ok(None);
                    }
                    Ok(Some(RawFrame {
                        source: 0,
                        width: width as u32,
                        height: height as u32,
                        captured_at,
                        pixels: std::mem::take(&mut *pixels),
                    }))
                })();

                let frame_result = frame_result.map(PendingRawFrame);

                // A failed pixel method can leave a pending JNI exception which
                // would prevent both cleanup calls. Clear it, then always attempt
                // to clear Kotlin's original slot even if native processing failed.
                if env.exception_check().unwrap_or(false) {
                    let _ = env.exception_clear();
                }
                let clear_result = env.call_method(&frame, "clear", "()V", &[]);
                if clear_result.is_err() && env.exception_check().unwrap_or(false) {
                    let _ = env.exception_clear();
                }
                if clear_result.is_err() {
                    return Err(io::Error::other(
                        "BrowserHost Kotlin frame slot could not be cleared",
                    ));
                }
                if env.exception_check().unwrap_or(false) {
                    let _ = env.exception_clear();
                }
                let binding = JObject::from(env.new_string(&binding_json).map_err(|_| {
                    io::Error::other("BrowserHost binding could not be checked after transfer")
                })?);
                let still_bound = env
                    .call_method(
                        self.endpoint.as_obj(),
                        "matchesBinding",
                        "(Ljava/lang/String;)Z",
                        &[JValue::Object(&binding)],
                    )
                    .and_then(|value| value.z())
                    .map_err(|_| {
                        io::Error::other("BrowserHost binding changed during frame transfer")
                    })?;
                if !still_bound {
                    return Ok(None);
                }
                frame_result.map(|mut frame| frame.0.take())
            })()
            .map(PendingRawFrame))
        });
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
        }
        result
            .map_err(|_| io::Error::other("BrowserHost frame JNI local scope failed"))?
            .map(|mut frame| frame.0.take())
    }

    fn reset(&mut self) -> io::Result<()> {
        self.cleanup.reset()
    }
}

fn zero_byte_array(env: &mut jni::JNIEnv<'_>, array: &JByteArray<'_>) -> io::Result<()> {
    const CHUNK: usize = 4096;
    let length = env.get_array_length(array).map_err(|_| {
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
        }
        io::Error::other("JNI byte-array length unavailable during zeroization")
    })? as usize;
    let zeros = [0i8; CHUNK];
    let mut offset = 0usize;
    let mut failed = false;
    while offset < length {
        let count = (length - offset).min(CHUNK);
        if env
            .set_byte_array_region(array, offset as i32, &zeros[..count])
            .is_err()
        {
            failed = true;
            if env.exception_check().unwrap_or(false) {
                let _ = env.exception_clear();
            }
        }
        offset += count;
    }
    if failed {
        Err(io::Error::other(
            "JNI byte array could not be fully zeroized",
        ))
    } else {
        Ok(())
    }
}

/// Input has its own owner adapter instead of reusing NativeSession's device.
/// Every operation carries the complete, tagged BrowserHost binding to the
/// Kotlin endpoint; matching request ids or generations alone is insufficient.
pub(crate) struct AndroidBrowserInputDevice {
    vm: Arc<JavaVM>,
    endpoint: GlobalRef,
    binding_json: String,
}

impl AndroidBrowserInputDevice {
    pub(crate) fn new(
        vm: Arc<JavaVM>,
        endpoint: GlobalRef,
        binding_json: String,
    ) -> io::Result<Self> {
        if binding_json.is_empty() || binding_json.len() > 8 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "BrowserHost input binding is invalid",
            ));
        }
        Ok(Self {
            vm,
            endpoint,
            binding_json,
        })
    }

    fn call_bound_bool(
        &self,
        method: &str,
        signature: &str,
        tail: &[JValue<'_, '_>],
    ) -> io::Result<bool> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|_| io::Error::other("BrowserHost input JVM attachment failed"))?;
        let binding = env
            .new_string(&self.binding_json)
            .map_err(|_| io::Error::other("BrowserHost input binding could not be prepared"))?;
        let binding = JObject::from(binding);
        let mut args = Vec::with_capacity(tail.len() + 1);
        args.push(JValue::Object(&binding));
        args.extend_from_slice(tail);
        call_bool(&mut env, self.endpoint.as_obj(), method, signature, &args)
    }

    fn accepted(&self, method: &str, signature: &str, tail: &[JValue<'_, '_>]) -> io::Result<()> {
        if self.call_bound_bool(method, signature, tail)? {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "BrowserHost input owner is stopped or stale",
            ))
        }
    }
}

impl InputDevice for AndroidBrowserInputDevice {
    fn check(&mut self) -> io::Result<()> {
        self.accepted("isInputActive", "(Ljava/lang/String;)Z", &[])
    }

    fn select_source(&mut self, source: u32, layout: InputLayout) -> io::Result<()> {
        if source != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "ungranted BrowserHost input source",
            ));
        }
        self.accepted(
            "selectInputSource",
            "(Ljava/lang/String;IIIII)Z",
            &[
                JValue::Int(source as i32),
                JValue::Int(layout.left),
                JValue::Int(layout.top),
                JValue::Int(i32::try_from(layout.width).map_err(io::Error::other)?),
                JValue::Int(i32::try_from(layout.height).map_err(io::Error::other)?),
            ],
        )
    }

    fn inject(&mut self, input: PlatformInput<'_>) -> io::Result<()> {
        match input {
            PlatformInput::Action(InputAction::Key { code, down }) => self.accepted(
                "sendHidKey",
                "(Ljava/lang/String;IZ)Z",
                &[JValue::Int(i32::from(*code)), JValue::Bool(u8::from(*down))],
            ),
            PlatformInput::Action(InputAction::Pointer { button, down, x, y }) => {
                let phase = match (button, down) {
                    (Some(1), true) => 1,
                    (None, false) => 2,
                    (Some(1), false) => 3,
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "Android supports primary touch input only",
                        ));
                    }
                };
                self.accepted(
                    "dispatchPointer",
                    "(Ljava/lang/String;III)Z",
                    &[JValue::Int(*x), JValue::Int(*y), JValue::Int(phase)],
                )
            }
            PlatformInput::Action(InputAction::Text(text)) => {
                let mut env = self
                    .vm
                    .attach_current_thread()
                    .map_err(|_| io::Error::other("BrowserHost input JVM attachment failed"))?;
                let binding = JObject::from(env.new_string(&self.binding_json).map_err(|_| {
                    io::Error::other("BrowserHost input binding could not be prepared")
                })?);
                let text = JObject::from(env.new_string(text).map_err(|_| {
                    io::Error::other("BrowserHost input text could not be prepared")
                })?);
                let args = [JValue::Object(&binding), JValue::Object(&text)];
                if call_bool(
                    &mut env,
                    self.endpoint.as_obj(),
                    "commitRemoteText",
                    "(Ljava/lang/String;Ljava/lang/String;)Z",
                    &args,
                )? {
                    Ok(())
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "BrowserHost text input is unavailable",
                    ))
                }
            }
            PlatformInput::Release(Button::Key(code)) => self.accepted(
                "sendHidKey",
                "(Ljava/lang/String;IZ)Z",
                &[JValue::Int(i32::from(code)), JValue::Bool(0)],
            ),
            PlatformInput::Release(Button::Pointer(_)) => {
                self.accepted("releasePointer", "(Ljava/lang/String;)Z", &[])
            }
        }
    }

    fn begin_reset(&mut self) -> io::Result<()> {
        self.accepted("releasePointer", "(Ljava/lang/String;)Z", &[])
    }

    fn reset(&mut self) -> io::Result<()> {
        self.accepted("stopInputAndAwait", "(Ljava/lang/String;)Z", &[])
    }
}

/// Projection-scoped playback capture for the BrowserHost endpoint. Its Kotlin
/// endpoint accepts only the full BrowserHost binding and joins AudioRecord on
/// reset before returning success.
pub(crate) struct AndroidBrowserAudioCaptureDevice {
    vm: Arc<JavaVM>,
    endpoint: GlobalRef,
    binding_json: String,
}

impl AndroidBrowserAudioCaptureDevice {
    pub(crate) fn new(
        vm: Arc<JavaVM>,
        endpoint: GlobalRef,
        binding_json: String,
    ) -> io::Result<Self> {
        if binding_json.is_empty() || binding_json.len() > 8 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "BrowserHost audio binding is invalid",
            ));
        }
        Ok(Self {
            vm,
            endpoint,
            binding_json,
        })
    }

    fn check_owner(&self, env: &mut jni::JNIEnv<'_>) -> jni::errors::Result<bool> {
        let binding = JObject::from(env.new_string(&self.binding_json)?);
        let matches = env
            .call_method(
                self.endpoint.as_obj(),
                "matchesBinding",
                "(Ljava/lang/String;)Z",
                &[JValue::Object(&binding)],
            )?
            .z()?;
        let active = env
            .call_method(self.endpoint.as_obj(), "isActive", "()Z", &[])?
            .z()?;
        Ok(matches && active)
    }
}

impl AudioDevice for AndroidBrowserAudioCaptureDevice {
    fn check(&mut self) -> io::Result<()> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|_| io::Error::other("BrowserHost audio JVM attachment failed"))?;
        let active = self
            .check_owner(&mut env)
            .map_err(|_| io::Error::other("BrowserHost audio binding check failed"))?;
        if active {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "BrowserHost AudioRecord owner is stopped or stale",
            ))
        }
    }

    fn reset(&mut self) -> io::Result<()> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|_| io::Error::other("BrowserHost audio JVM attachment failed"))?;
        let binding =
            JObject::from(env.new_string(&self.binding_json).map_err(|_| {
                io::Error::other("BrowserHost audio binding could not be prepared")
            })?);
        let result = env
            .call_method(
                self.endpoint.as_obj(),
                "resetAndAwait",
                "(Ljava/lang/String;)Z",
                &[JValue::Object(&binding)],
            )
            .and_then(|value| value.z());
        match result {
            Ok(true) => Ok(()),
            Ok(false) => Err(io::Error::other(
                "BrowserHost AudioRecord cleanup is not confirmed",
            )),
            Err(_) => {
                if env.exception_check().unwrap_or(false) {
                    let _ = env.exception_clear();
                }
                Err(io::Error::other("BrowserHost AudioRecord cleanup failed"))
            }
        }
    }
}

impl AudioCaptureDevice for AndroidBrowserAudioCaptureDevice {
    fn poll_chunk(&mut self) -> io::Result<Option<CapturedAudio>> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|_| io::Error::other("BrowserHost audio JVM attachment failed"))?;
        if !self
            .check_owner(&mut env)
            .map_err(|_| io::Error::other("BrowserHost audio binding check failed"))?
        {
            return Ok(None);
        }
        let object = env
            .call_method(self.endpoint.as_obj(), "pollCaptureChunk", "()[B", &[])
            .and_then(|value| value.l())
            .map_err(|_| io::Error::other("BrowserHost AudioRecord read failed"))?;
        if object.is_null() {
            return Ok(None);
        }
        let array = JByteArray::from(object);
        let copied = env.convert_byte_array(&array);
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
        }
        let bytes = copied.map(Zeroizing::new);
        let cleared = zero_byte_array(&mut env, &array);
        let bytes = bytes.map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "BrowserHost audio packet is invalid",
            )
        })?;
        cleared.map_err(|_| io::Error::other("BrowserHost audio packet could not be cleared"))?;
        if bytes.len() != AUDIO_PACKET_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "BrowserHost audio packet exceeded its fixed budget",
            ));
        }
        let pts = u64::from_le_bytes(bytes[..8].try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "BrowserHost audio timestamp is invalid",
            )
        })?);
        let captured_nanos = i64::from_le_bytes(bytes[8..16].try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "BrowserHost audio clock is invalid",
            )
        })?);
        let now_nanos = env
            .call_static_method("java/lang/System", "nanoTime", "()J", &[])
            .and_then(|value| value.j())
            .map_err(|_| io::Error::other("Android monotonic clock unavailable"))?;
        let Some(age) = now_nanos
            .checked_sub(captured_nanos)
            .filter(|age| *age >= 0 && *age <= 100_000_000)
        else {
            return Ok(None);
        };
        let captured_at = Instant::now()
            .checked_sub(Duration::from_nanos(age as u64))
            .ok_or_else(|| io::Error::other("BrowserHost audio clock underflow"))?;
        let samples = bytes[16..]
            .chunks_exact(2)
            .map(|sample| i16::from_le_bytes([sample[0], sample[1]]))
            .collect();
        Ok(Some(CapturedAudio {
            captured_at,
            chunk: AudioChunk {
                source: 0,
                channels: AUDIO_CHANNELS,
                pts_48khz: pts,
                samples,
            },
        }))
    }
}

fn call_bool(
    env: &mut jni::JNIEnv<'_>,
    target: &JObject<'_>,
    method: &str,
    signature: &str,
    args: &[JValue<'_, '_>],
) -> io::Result<bool> {
    match env
        .call_method(target, method, signature, args)
        .and_then(|value| value.z())
    {
        Ok(value) => Ok(value),
        Err(_) => {
            if env.exception_check().unwrap_or(false) {
                let _ = env.exception_clear();
            }
            Err(io::Error::other(
                "BrowserHost platform endpoint rejected the operation",
            ))
        }
    }
}

#[cfg(test)]
mod capture_owner_cleanup_tests {
    use super::CaptureOwnerCleanup;
    use std::{
        io,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
    };

    struct LeaseFlag(Arc<AtomicBool>);
    impl Drop for LeaseFlag {
        fn drop(&mut self) {
            self.0.store(false, Ordering::SeqCst);
        }
    }

    #[test]
    fn unattached_source_drop_retires_authorization_before_stopping_its_owner() {
        let live = Arc::new(AtomicBool::new(true));
        let stops = Arc::new(AtomicUsize::new(0));
        let checked_live = Arc::clone(&live);
        let checked_stops = Arc::clone(&stops);
        let cleanup = CaptureOwnerCleanup::new(LeaseFlag(Arc::clone(&live)), move || {
            assert!(!checked_live.load(Ordering::SeqCst));
            checked_stops.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        drop(cleanup);
        assert!(!live.load(Ordering::SeqCst));
        assert_eq!(stops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn acknowledged_reset_is_idempotent_including_the_later_drop() {
        let live = Arc::new(AtomicBool::new(true));
        let stops = Arc::new(AtomicUsize::new(0));
        let checked_live = Arc::clone(&live);
        let checked_stops = Arc::clone(&stops);
        let mut cleanup = CaptureOwnerCleanup::new(LeaseFlag(Arc::clone(&live)), move || {
            assert!(!checked_live.load(Ordering::SeqCst));
            checked_stops.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        assert!(cleanup.reset().is_ok());
        assert!(cleanup.reset().is_ok());
        drop(cleanup);
        assert!(!live.load(Ordering::SeqCst));
        assert_eq!(stops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn failed_or_panicked_reset_stays_retired_and_drop_retries_cleanup() {
        for panic_first in [false, true] {
            let live = Arc::new(AtomicBool::new(true));
            let stops = Arc::new(AtomicUsize::new(0));
            let checked_live = Arc::clone(&live);
            let checked_stops = Arc::clone(&stops);
            let mut cleanup = CaptureOwnerCleanup::new(LeaseFlag(Arc::clone(&live)), move || {
                assert!(!checked_live.load(Ordering::SeqCst));
                if checked_stops.fetch_add(1, Ordering::SeqCst) == 0 {
                    assert!(!panic_first, "synthetic capture cleanup panic");
                    return Err(io::Error::other("synthetic unconfirmed stop"));
                }
                Ok(())
            });
            assert!(cleanup.reset().is_err());
            assert!(!live.load(Ordering::SeqCst));
            drop(cleanup);
            assert_eq!(stops.load(Ordering::SeqCst), 2);
        }
    }

    #[test]
    fn unconfirmed_cleanup_never_reinstates_the_activation_lease() {
        let live = Arc::new(AtomicBool::new(true));
        let stops = Arc::new(AtomicUsize::new(0));
        let checked_live = Arc::clone(&live);
        let checked_stops = Arc::clone(&stops);
        let mut cleanup = CaptureOwnerCleanup::new(LeaseFlag(Arc::clone(&live)), move || {
            assert!(!checked_live.load(Ordering::SeqCst));
            checked_stops.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::other("synthetic unconfirmed stop"))
        });
        assert!(cleanup.reset().is_err());
        assert!(cleanup.reset().is_err());
        drop(cleanup);
        assert!(!live.load(Ordering::SeqCst));
        assert_eq!(stops.load(Ordering::SeqCst), 3);
    }
}
