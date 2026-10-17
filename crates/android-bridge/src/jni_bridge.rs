mod browser_data;
mod native_network;
mod services;

use crate::browser_capture::{JniAndroidBrowserHostPort, browser_host_activation_lease_active};
use crate::browser_host::AndroidBrowserHostPort;
use crate::file_transfer::AndroidFileIdentity;
use crate::{
    handle_registry::HandleRegistry,
    management::{AndroidManagementSession, AndroidPermissionChoices},
    platform_audio::AndroidAudioDevice,
    platform_input::AndroidInputDevice,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jni::{
    JNIEnv,
    objects::{JByteArray, JClass, JObject, JString, JValue},
    sys::{jboolean, jint, jlong, jobject},
};
use nestlink_app_core::NativeClipboardBinding;
use nestlink_app_core::NativeSessionBinding;
use nestlink_app_core::{ApprovedServer, NativeAudioBinding, NativeAudioRole};
use nestlink_auth::Secret;
use nestlink_identity::InstallationIdentity;
use nestlink_media_codec::{EncodedVideo, VideoConfig, Vp8Encoder};
use nestlink_sdk::DeviceIdentity;
use std::collections::HashMap;
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicI64, Ordering},
};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

static NEXT_HANDLE: AtomicI64 = AtomicI64::new(1);
static HANDLES: OnceLock<HandleRegistry<AndroidManagementSession>> = OnceLock::new();
static CONNECT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static NEXT_VIDEO_ENCODER: AtomicI64 = AtomicI64::new(1);
static VIDEO_ENCODERS: OnceLock<Mutex<HashMap<i64, VideoEncoderContext>>> = OnceLock::new();

struct VideoEncoderContext {
    encoder: Vp8Encoder,
    frame_bytes: usize,
}

fn handles() -> &'static HandleRegistry<AndroidManagementSession> {
    HANDLES.get_or_init(HandleRegistry::default)
}

fn connect_lock() -> &'static Mutex<()> {
    CONNECT_LOCK.get_or_init(|| Mutex::new(()))
}

fn video_encoders() -> &'static Mutex<HashMap<i64, VideoEncoderContext>> {
    VIDEO_ENCODERS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn read_string(env: &mut JNIEnv<'_>, value: JString<'_>) -> Result<String, String> {
    env.get_string(&value)
        .map(|value| value.into())
        .map_err(|_| "invalid text supplied by Android".to_owned())
}

fn get_session(handle: jlong) -> Result<Arc<AndroidManagementSession>, String> {
    handles().get(handle)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AndroidAudioBindingJson {
    request_id: String,
    connection_generation: u64,
    role: String,
}

fn read_audio_binding(json: String) -> Result<NativeAudioBinding, String> {
    if json.len() > 4_096 {
        return Err("Android audio binding exceeds its size limit".to_owned());
    }
    let binding: AndroidAudioBindingJson =
        serde_json::from_str(&json).map_err(|_| "Android audio binding is invalid".to_owned())?;
    if binding.request_id.is_empty() || binding.connection_generation == 0 {
        return Err("Android audio binding identity is invalid".to_owned());
    }
    let role = match binding.role.as_str() {
        "HostCapture" => NativeAudioRole::HostCapture,
        "ControllerPlayback" => NativeAudioRole::ControllerPlayback,
        _ => return Err("Android audio binding role is invalid".to_owned()),
    };
    Ok(NativeAudioBinding {
        request_id: binding.request_id,
        connection_generation: binding.connection_generation,
        role,
    })
}

fn read_session_binding(json: String) -> Result<NativeSessionBinding, String> {
    if json.len() > 4_096 {
        return Err("Android session binding exceeds its size limit".to_owned());
    }
    let binding: NativeSessionBinding =
        serde_json::from_str(&json).map_err(|_| "Android session binding is invalid".to_owned())?;
    if binding.request_id.is_empty() || binding.connection_generation == 0 {
        return Err("Android session binding identity is invalid".to_owned());
    }
    Ok(binding)
}

fn read_file_identity(json: String) -> Result<AndroidFileIdentity, String> {
    if json.len() > 4_096 {
        return Err("Android file-session identity exceeds its size limit".to_owned());
    }
    let identity: AndroidFileIdentity = serde_json::from_str(&json)
        .map_err(|_| "Android file-session identity is invalid".to_owned())?;
    if identity.binding.request_id.is_empty()
        || identity.binding.connection_generation == 0
        || identity.core_generation == 0
    {
        return Err("Android file-session identity is incomplete".to_owned());
    }
    Ok(identity)
}

fn read_clipboard_binding(json: String) -> Result<NativeClipboardBinding, String> {
    if json.len() > 4_096 {
        return Err("stale_binding".to_owned());
    }
    let binding: NativeClipboardBinding =
        serde_json::from_str(&json).map_err(|_| "stale_binding".to_owned())?;
    if binding.request_id.is_empty()
        || binding.request_id.len() > 128
        || binding.connection_generation == 0
        || binding.core_generation == 0
    {
        return Err("stale_binding".to_owned());
    }
    Ok(binding)
}

fn throw(env: &mut JNIEnv<'_>, message: &str) {
    let _ = env.throw_new("java/lang/IllegalStateException", message);
}

fn java_string(env: &mut JNIEnv<'_>, value: Result<String, String>) -> jobject {
    match value {
        Ok(value) => env
            .new_string(value)
            .map(|value| value.into_raw())
            .unwrap_or_else(|_| {
                throw(env, "unable to create Android response");
                JObject::null().into_raw()
            }),
        Err(error) => {
            throw(env, &error);
            JObject::null().into_raw()
        }
    }
}

fn nullable_java_string(env: &mut JNIEnv<'_>, value: Result<Option<String>, String>) -> jobject {
    match value {
        Ok(Some(value)) => java_string(env, Ok(value)),
        Ok(None) => JObject::null().into_raw(),
        Err(error) => {
            throw(env, &error);
            JObject::null().into_raw()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeConnect(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    origin: JString<'_>,
    deployment_id: JString<'_>,
    issuer_key: JString<'_>,
    device_id: JString<'_>,
    seed: JByteArray<'_>,
) -> jlong {
    let result = (|| {
        let _connect = connect_lock()
            .lock()
            .map_err(|_| "Android connect gate is unavailable".to_owned())?;
        if !handles().is_empty()? {
            return Err("close the existing Android native handle and finish its cleanup before connecting again".to_owned());
        }
        let origin = read_string(&mut env, origin)?;
        let deployment_id = read_string(&mut env, deployment_id)?;
        let issuer_key = read_string(&mut env, issuer_key)?;
        let device_id = read_string(&mut env, device_id)?;
        let issuer = if deployment_id.trim().is_empty() && issuer_key.trim().is_empty() {
            [0; 32]
        } else {
            URL_SAFE_NO_PAD
                .decode(issuer_key)
                .map_err(|_| "server signing key must be base64url without padding".to_owned())?
                .try_into()
                .map_err(|_| "server signing key must contain exactly 32 bytes".to_owned())?
        };
        let parsed_device_id = Uuid::parse_str(&device_id)
            .map_err(|_| "Android installation identifier is invalid".to_owned())?;
        if parsed_device_id.is_nil() || parsed_device_id.hyphenated().to_string() != device_id {
            return Err("Android installation identifier is invalid".to_owned());
        }
        let mut seed = Zeroizing::new(
            env.convert_byte_array(&seed)
                .map_err(|_| "Android installation seed is unavailable".to_owned())?,
        );
        if seed.len() != 32 {
            return Err("Android installation seed must contain 32 bytes".to_owned());
        }
        let mut seed_bytes = [0u8; 32];
        seed_bytes.copy_from_slice(&seed);
        seed.fill(0);
        let installation = DeviceIdentity {
            device_id,
            identity: InstallationIdentity::from_seed_zeroizing(&mut seed_bytes),
        };
        // Resolve the app class from this Java-entered JNI frame. Background
        // Rust worker threads cannot safely FindClass app classes themselves.
        let browser_host_port: Arc<dyn AndroidBrowserHostPort> =
            Arc::new(JniAndroidBrowserHostPort::from_env(&mut env).map_err(|_| {
                "Android BrowserHost coordinator could not be initialized".to_owned()
            })?);
        let session = AndroidManagementSession::new(installation, Some(browser_host_port))?;
        if let Err(error) = session.verify_server(ApprovedServer {
            origin: origin.trim().to_owned(),
            deployment_id: deployment_id.trim().to_owned(),
            permit_issuer: issuer,
            allow_loopback_http: false,
        }) {
            let _ = session.shutdown();
            return Err(error);
        }
        let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
        if handle <= 0 {
            let _ = session.shutdown();
            return Err("Android app-core handle space is exhausted".to_owned());
        }
        let session = Arc::new(session);
        if let Err(error) = handles().insert(handle, Arc::clone(&session)) {
            let _ = session.shutdown();
            return Err(error);
        }
        Ok(handle)
    })();
    match result {
        Ok(handle) => handle,
        Err(error) => {
            throw(&mut env, &error);
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeLogin(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    username: JString<'_>,
    password: JString<'_>,
    factor: JString<'_>,
) -> jobject {
    let result = (|| {
        let username = read_string(&mut env, username)?;
        let mut password = Zeroizing::new(read_string(&mut env, password)?);
        let factor = if factor.is_null() {
            None
        } else {
            let mut value = Zeroizing::new(read_string(&mut env, factor)?);
            Some(Secret::from_text(std::mem::take(&mut *value)))
        };
        get_session(handle)?.login(
            username,
            Secret::from_text(std::mem::take(&mut *password)),
            factor,
        )
    })();
    java_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeMe(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jobject {
    let result = get_session(handle).and_then(|session| session.me_json());
    java_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeDevices(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jobject {
    let result = get_session(handle).and_then(|session| session.devices_json());
    java_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeRemoteRequest(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    request_id: JString<'_>,
) -> jobject {
    let result = (|| {
        let request_id = read_string(&mut env, request_id)?;
        get_session(handle)?.remote_request_json(request_id)
    })();
    java_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeRemoteRequests(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jobject {
    let result = get_session(handle).and_then(|session| session.remote_requests_json());
    java_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeTrustedDevices(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    host_device_id: JString<'_>,
) -> jobject {
    let result = (|| {
        let host_device_id = read_string(&mut env, host_device_id)?;
        get_session(handle)?.trusted_devices_json(host_device_id)
    })();
    java_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeTrustRemote(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    request_id: JString<'_>,
    expected_revision: jlong,
    expires_at_unix_ms: jlong,
) -> jobject {
    let result = (|| {
        let request_id = read_string(&mut env, request_id)?;
        let expected_revision = u64::try_from(expected_revision)
            .map_err(|_| "invalid trusted-device revision".to_owned())?;
        let expires_at_unix_ms = u64::try_from(expires_at_unix_ms)
            .map_err(|_| "invalid trusted-device expiry".to_owned())?;
        get_session(handle)?.trust_remote(request_id, expected_revision, expires_at_unix_ms)
    })();
    java_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeRevokeDeviceTrust(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    host_device_id: JString<'_>,
    controller_device_id: JString<'_>,
    expected_revision: jlong,
) -> jobject {
    let result = (|| {
        let host_device_id = read_string(&mut env, host_device_id)?;
        let controller_device_id = read_string(&mut env, controller_device_id)?;
        let expected_revision = u64::try_from(expected_revision)
            .map_err(|_| "invalid trusted-device revision".to_owned())?;
        get_session(handle)?.revoke_device_trust(
            host_device_id,
            controller_device_id,
            expected_revision,
        )
    })();
    java_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeRemotePassword(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    host_device_id: JString<'_>,
) -> jobject {
    let result = (|| {
        let host_device_id = read_string(&mut env, host_device_id)?;
        get_session(handle)?.remote_password_json(host_device_id)
    })();
    java_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeConfigureRemotePassword(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    settings_json: JString<'_>,
    password: JString<'_>,
) -> jobject {
    let result = (|| {
        let settings_json = read_string(&mut env, settings_json)?;
        let mut password = Zeroizing::new(read_string(&mut env, password)?);
        if !(12..=1_024).contains(&password.len()) {
            return Err("remote password must be 12 to 1024 UTF-8 bytes".to_owned());
        }
        get_session(handle)?.configure_remote_password(
            settings_json,
            Secret::from_text(std::mem::take(&mut *password)),
        )
    })();
    java_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeRevokeRemotePassword(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    expected_revision: jlong,
) -> jobject {
    let result = u64::try_from(expected_revision)
        .map_err(|_| "invalid remote password revision".to_owned())
        .and_then(|revision| get_session(handle)?.revoke_remote_password(revision));
    java_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeRemotePasswordOffer(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    request_id: JString<'_>,
) -> jobject {
    let result = (|| {
        let request_id = read_string(&mut env, request_id)?;
        get_session(handle)?.remote_password_offer_json(request_id)
    })();
    java_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeAuthorizeRemotePassword(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    request_id: JString<'_>,
    expected_revision: jlong,
    password: JString<'_>,
) -> jobject {
    let result = (|| {
        let request_id = read_string(&mut env, request_id)?;
        let expected_revision = u64::try_from(expected_revision)
            .map_err(|_| "invalid remote password revision".to_owned())?;
        let mut password = Zeroizing::new(read_string(&mut env, password)?);
        if !(12..=1_024).contains(&password.len()) {
            return Err("remote password must be 12 to 1024 UTF-8 bytes".to_owned());
        }
        get_session(handle)?.authorize_remote_password(
            request_id,
            expected_revision,
            Secret::from_text(std::mem::take(&mut *password)),
        )
    })();
    java_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeApproveRemote(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    request_id: JString<'_>,
    expected_nonce: JString<'_>,
    expected_policy_revision: jlong,
    approved: jboolean,
    approve_input: jboolean,
    approve_audio: jboolean,
    approve_file_read: jboolean,
    approve_file_write: jboolean,
    approve_clipboard_read: jboolean,
    approve_clipboard_write: jboolean,
) -> jobject {
    let result = (|| {
        let request_id = read_string(&mut env, request_id)?;
        let expected_nonce = read_string(&mut env, expected_nonce)?;
        let expected_policy_revision = u64::try_from(expected_policy_revision)
            .map_err(|_| "invalid remote request policy revision".to_owned())?;
        get_session(handle)?.approve_remote(
            request_id,
            expected_nonce,
            expected_policy_revision,
            approved != 0,
            AndroidPermissionChoices {
                input: approve_input != 0,
                audio: approve_audio != 0,
                file_read: approve_file_read != 0,
                file_write: approve_file_write != 0,
                clipboard_read: approve_clipboard_read != 0,
                clipboard_write: approve_clipboard_write != 0,
            },
        )
    })();
    java_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeRequestView(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    host_device_id: JString<'_>,
    request_input: jboolean,
    request_audio: jboolean,
    request_file_read: jboolean,
    request_file_write: jboolean,
    request_clipboard_read: jboolean,
    request_clipboard_write: jboolean,
) -> jobject {
    let result = (|| {
        let host_device_id = read_string(&mut env, host_device_id)?;
        get_session(handle)?.request_view(
            host_device_id,
            AndroidPermissionChoices {
                input: request_input != 0,
                audio: request_audio != 0,
                file_read: request_file_read != 0,
                file_write: request_file_write != 0,
                clipboard_read: request_clipboard_read != 0,
                clipboard_write: request_clipboard_write != 0,
            },
        )
    })();
    java_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeCancelRemote(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    request_id: JString<'_>,
) {
    let result = (|| {
        let request_id = read_string(&mut env, request_id)?;
        get_session(handle)?.revoke_remote(request_id)
    })();
    if let Err(error) = result {
        throw(&mut env, &error);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeStartNativeSession(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    request_id: JString<'_>,
) -> jobject {
    let result = (|| {
        let request_id = read_string(&mut env, request_id)?;
        get_session(handle)?.start_native_session(request_id)
    })();
    java_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeStopNativeSession(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    request_id: JString<'_>,
) -> jobject {
    let result = (|| {
        let request_id = read_string(&mut env, request_id)?;
        get_session(handle)?.stop_native_session(request_id)
    })();
    java_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeNativeSessionStatus(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jobject {
    let result = get_session(handle).and_then(|session| session.native_session_json());
    java_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeStartBrowserHost(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    request_id: JString<'_>,
) -> jobject {
    let result = (|| {
        let request_id = read_string(&mut env, request_id)?;
        get_session(handle)?.start_browser_host(request_id)
    })();
    java_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeStopBrowserHost(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    request_id: JString<'_>,
) -> jobject {
    let result = (|| {
        let request_id = read_string(&mut env, request_id)?;
        get_session(handle)?.stop_browser_host(request_id)
    })();
    java_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeBrowserHostStatus(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jobject {
    let result = get_session(handle).and_then(|session| session.browser_host_json());
    java_string(&mut env, result)
}

/// Rechecks the real BrowserHost media lease on the Android capture worker,
/// after Handler scheduling and immediately before platform activation.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeBrowserHostActivationLeaseActive(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    binding_json: JString<'_>,
) -> jboolean {
    let active = read_string(&mut env, binding_json)
        .ok()
        .is_some_and(|binding| browser_host_activation_lease_active(&binding));
    u8::from(active)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeAudioBinding(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jobject {
    let result = get_session(handle).and_then(|session| session.native_audio_binding_json());
    nullable_java_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeAttachNativeAudioCapture(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    binding_json: JString<'_>,
    endpoint: JObject<'_>,
) {
    let result = (|| {
        if endpoint.is_null() {
            return Err("Android audio capture endpoint is unavailable".to_owned());
        }
        let binding = read_audio_binding(read_string(&mut env, binding_json)?)?;
        let vm = env
            .get_java_vm()
            .map_err(|_| "Android audio JVM is unavailable".to_owned())?;
        let endpoint = env
            .new_global_ref(endpoint)
            .map_err(|_| "Android audio capture endpoint could not be retained".to_owned())?;
        get_session(handle)?.attach_native_audio_capture(
            &binding,
            AndroidAudioDevice::new(vm, endpoint, binding.clone(), true),
        )
    })();
    if let Err(error) = result {
        throw(&mut env, &error);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeAttachNativeAudioPlayback(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    binding_json: JString<'_>,
    endpoint: JObject<'_>,
) {
    let result = (|| {
        if endpoint.is_null() {
            return Err("Android audio playback endpoint is unavailable".to_owned());
        }
        let binding = read_audio_binding(read_string(&mut env, binding_json)?)?;
        let vm = env
            .get_java_vm()
            .map_err(|_| "Android audio JVM is unavailable".to_owned())?;
        let endpoint = env
            .new_global_ref(endpoint)
            .map_err(|_| "Android audio playback endpoint could not be retained".to_owned())?;
        get_session(handle)?.attach_native_audio_playback(
            &binding,
            AndroidAudioDevice::new(vm, endpoint, binding.clone(), false),
        )
    })();
    if let Err(error) = result {
        throw(&mut env, &error);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeNativeAudioWorkerStatus(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    binding_json: JString<'_>,
) -> jobject {
    let result = (|| {
        let binding = read_audio_binding(read_string(&mut env, binding_json)?)?;
        get_session(handle)?.native_audio_worker_status_json(&binding)
    })();
    nullable_java_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeFailNativeAudio(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    binding_json: JString<'_>,
) {
    let result = (|| {
        let binding = read_audio_binding(read_string(&mut env, binding_json)?)?;
        get_session(handle)?.fail_native_audio(&binding)
    })();
    if let Err(error) = result {
        throw(&mut env, &error);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeDeviceId(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jobject {
    let result = get_session(handle).and_then(|session| session.device_id());
    java_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeRegisterController(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    name: JString<'_>,
) {
    let result = (|| {
        let name = read_string(&mut env, name)?;
        get_session(handle)?.register_controller(name)
    })();
    if let Err(error) = result {
        throw(&mut env, &error);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeRegisterHost(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    name: JString<'_>,
) {
    let result = (|| {
        let name = read_string(&mut env, name)?;
        get_session(handle)?.register_host(name)
    })();
    if let Err(error) = result {
        throw(&mut env, &error);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeReportPlatformCapture(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    active: jboolean,
    session_binding_json: JString<'_>,
    reason: JString<'_>,
) -> jobject {
    let result = (|| {
        let binding = if session_binding_json.is_null() {
            None
        } else {
            Some(read_session_binding(read_string(
                &mut env,
                session_binding_json,
            )?)?)
        };
        let reason = read_string(&mut env, reason)?;
        get_session(handle)?.report_platform_capture(active != 0, reason, binding)
    })();
    java_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativePlatformCaptureStatus(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jobject {
    let result = get_session(handle).and_then(|session| session.platform_capture_json());
    java_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeCanStartHostCapture(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jboolean {
    match get_session(handle).and_then(|session| session.require_host_capture_eligible()) {
        Ok(()) => 1,
        Err(error) => {
            throw(&mut env, &error);
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeHostSessionBinding(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jobject {
    let result = get_session(handle).and_then(|session| session.host_session_binding_json());
    nullable_java_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeNetworkChanged(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    facts_json: JString<'_>,
    observer_active: jboolean,
    elapsed_realtime_ms: jlong,
    uptime_ms: jlong,
) {
    let result = (|| {
        let session = get_session(handle)?;
        match read_string(&mut env, facts_json) {
            Ok(facts_json) => session.report_network_facts(
                &facts_json,
                observer_active != 0,
                elapsed_realtime_ms,
                uptime_ms,
            ),
            Err(error) => {
                let _ = session.report_network_facts("", false, elapsed_realtime_ms, uptime_ms);
                Err(error)
            }
        }
    })();
    if let Err(error) = result {
        throw(&mut env, &error);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeConfigureHostVideoStream(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    session_binding_json: JString<'_>,
    source: jint,
    width: jint,
    height: jint,
    layout_epoch: jlong,
) {
    let result = (|| {
        let session_binding = read_session_binding(read_string(&mut env, session_binding_json)?)?;
        let source = u32::try_from(source).map_err(|_| "invalid video source".to_owned())?;
        let width = u32::try_from(width).map_err(|_| "invalid video width".to_owned())?;
        let height = u32::try_from(height).map_err(|_| "invalid video height".to_owned())?;
        let layout_epoch =
            u64::try_from(layout_epoch).map_err(|_| "invalid video layout epoch".to_owned())?;
        get_session(handle)?.configure_host_video_stream(
            &session_binding,
            source,
            width,
            height,
            layout_epoch,
        )
    })();
    if let Err(error) = result {
        throw(&mut env, &error);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeHostCapturePts(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    binding_json: JString<'_>,
    age_ns: jlong,
) -> jlong {
    let result = (|| {
        let binding = read_session_binding(read_string(&mut env, binding_json)?)?;
        let age = u64::try_from(age_ns).map_err(|_| "negative capture age".to_owned())?;
        get_session(handle)?.host_capture_pts(&binding, age)
    })();
    match result {
        Ok(pts) => pts as jlong,
        Err(error) => {
            throw(&mut env, &error);
            0
        }
    }
}
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeHostDisplayReady(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    binding_json: JString<'_>,
) -> jlong {
    let result = (|| {
        let binding = read_session_binding(read_string(&mut env, binding_json)?)?;
        get_session(handle)?.host_display_ready(&binding)
    })();
    match result {
        Ok(epoch) => epoch as jlong,
        Err(error) => {
            throw(&mut env, &error);
            0
        }
    }
}
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeNativeDisplays(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jobject {
    let result = get_session(handle).and_then(|session| session.native_displays_json());
    nullable_java_string(&mut env, result)
}
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeSelectRemoteDisplay(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    request_json: JString<'_>,
) -> jobject {
    let result = (|| {
        let request = read_string(&mut env, request_json)?;
        get_session(handle)?.select_remote_display(&request)
    })();
    java_string(&mut env, result)
}
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeClearHostVideoStreamFor(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    session_binding_json: JString<'_>,
) {
    let result: Result<(), String> = (|| {
        let binding = read_session_binding(read_string(&mut env, session_binding_json)?)?;
        get_session(handle)?.clear_host_video_stream_for(&binding);
        Ok(())
    })();
    if let Err(error) = result {
        throw(&mut env, &error);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeHostVideoKeyframeNeeded(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    session_binding_json: JString<'_>,
    source: jint,
    layout_epoch: jlong,
    width: jint,
    height: jint,
) -> jboolean {
    let result = (|| {
        let session_binding = read_session_binding(read_string(&mut env, session_binding_json)?)?;
        let source = u32::try_from(source).map_err(|_| "invalid video source".to_owned())?;
        let layout_epoch =
            u64::try_from(layout_epoch).map_err(|_| "invalid video layout epoch".to_owned())?;
        let width = u32::try_from(width).map_err(|_| "invalid video width".to_owned())?;
        let height = u32::try_from(height).map_err(|_| "invalid video height".to_owned())?;
        get_session(handle)?.native_video_keyframe_needed(
            &session_binding,
            nestlink_app_core::NativeVideoBinding {
                source,
                width,
                height,
                layout_epoch,
            },
        )
    })();
    match result {
        Ok(needed) => u8::from(needed),
        Err(error) => {
            throw(&mut env, &error);
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeSendHostVideo(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    session_binding_json: JString<'_>,
    source: jint,
    layout_epoch: jlong,
    width: jint,
    height: jint,
    pts_90khz: jlong,
    keyframe: jboolean,
    payload: JByteArray<'_>,
) -> jboolean {
    let result = (|| {
        let session_binding = read_session_binding(read_string(&mut env, session_binding_json)?)?;
        let source = u32::try_from(source).map_err(|_| "invalid video source".to_owned())?;
        let layout_epoch =
            u64::try_from(layout_epoch).map_err(|_| "invalid video layout epoch".to_owned())?;
        let width = u32::try_from(width).map_err(|_| "invalid video width".to_owned())?;
        let height = u32::try_from(height).map_err(|_| "invalid video height".to_owned())?;
        let pts_90khz = u64::try_from(pts_90khz)
            .map_err(|_| "invalid video presentation timestamp".to_owned())?;
        let mut payload = Zeroizing::new(
            env.convert_byte_array(&payload)
                .map_err(|_| "encoded Android video frame is unavailable".to_owned())?,
        );
        let session = get_session(handle)?;
        session.send_host_video_frame(
            &session_binding,
            nestlink_app_core::NativeVideoBinding {
                source,
                width,
                height,
                layout_epoch,
            },
            pts_90khz,
            keyframe != 0,
            std::mem::take(&mut *payload),
        )
    })();
    match result {
        Ok(()) => 1,
        Err(error) => {
            throw(&mut env, &error);
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeRemoteVideoLayout(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jobject {
    let result = (|| {
        let layout = get_session(handle)?.remote_video_layout()?;
        layout
            .map(|layout| {
                serde_json::to_string(&serde_json::json!({
                    "connectionGeneration": layout.epoch.connection,
                    "layoutEpoch": layout.epoch.layout,
                    "source": layout.source,
                    "width": layout.width,
                    "height": layout.height,
                }))
                .map_err(|_| "Android remote video layout could not be encoded".to_owned())
            })
            .transpose()
    })();
    nullable_java_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativePollRemoteVideo(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jobject {
    let result = (|| {
        let frame = get_session(handle)?.poll_remote_video()?;
        frame
            .map(|frame| decoded_video_object(&mut env, frame).map(|object| object.into_raw()))
            .transpose()
    })();
    match result {
        Ok(Some(frame)) => frame,
        Ok(None) => JObject::null().into_raw(),
        Err(error) => {
            throw(&mut env, &error);
            JObject::null().into_raw()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeHostInputAuthorized(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    session_binding_json: JString<'_>,
) -> jboolean {
    let result: Result<bool, String> = (|| {
        let binding = read_session_binding(read_string(&mut env, session_binding_json)?)?;
        Ok(get_session(handle)?.native_host_input_authorized(&binding))
    })();
    match result {
        Ok(authorized) => u8::from(authorized),
        Err(error) => {
            throw(&mut env, &error);
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeAttachHostInput(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    session_binding_json: JString<'_>,
    source: jint,
    layout_epoch: jlong,
    left: jint,
    top: jint,
    width: jint,
    height: jint,
) {
    let result = (|| {
        let session_binding = read_session_binding(read_string(&mut env, session_binding_json)?)?;
        let source =
            u32::try_from(source).map_err(|_| "invalid Android input source".to_owned())?;
        let layout_epoch = u64::try_from(layout_epoch)
            .map_err(|_| "invalid Android input layout epoch".to_owned())?;
        let width = u32::try_from(width).map_err(|_| "invalid Android input width".to_owned())?;
        let height =
            u32::try_from(height).map_err(|_| "invalid Android input height".to_owned())?;
        let session = get_session(handle)?;
        if !session.native_host_input_authorized(&session_binding) {
            return Err("Android host has no approved Input permission".to_owned());
        }

        let class = env
            .find_class("com/zhanry/nestlink/AndroidInputBridge")
            .map_err(|_| "Android input service is unavailable".to_owned())?;
        let bridge = env
            .get_static_field(
                class,
                "INSTANCE",
                "Lcom/zhanry/nestlink/AndroidInputBridge;",
            )
            .and_then(|value| value.l())
            .map_err(|_| "Android input service is unavailable".to_owned())?;
        let accessibility_ready = env
            .call_method(&bridge, "isAccessibilityRunning", "()Z", &[])
            .and_then(|value| value.z())
            .map_err(|_| "Android Accessibility Service is not active".to_owned())?;
        if !accessibility_ready {
            return Err("enable NestLink Accessibility before attaching host input".to_owned());
        }
        let bridge = env
            .new_global_ref(bridge)
            .map_err(|_| "Android input service could not be retained".to_owned())?;
        let vm = env
            .get_java_vm()
            .map_err(|_| "Android input JVM is unavailable".to_owned())?;
        let device = AndroidInputDevice::new(vm, bridge);
        session.attach_native_input_device(
            &session_binding,
            source,
            layout_epoch,
            device,
            nestlink_remote::input::InputLayout {
                left,
                top,
                width,
                height,
            },
        )
    })();
    if let Err(error) = result {
        throw(&mut env, &error);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeInputLayout(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jobject {
    let result = get_session(handle).and_then(|session| {
        session
            .native_input_layout()?
            .map(|layout| {
                serde_json::to_string(&layout)
                    .map_err(|_| "Android input layout could not be encoded".to_owned())
            })
            .transpose()
    });
    nullable_java_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeSendInput(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    binding_json: JString<'_>,
    action_json: JString<'_>,
) {
    let result = (|| {
        let binding_json = read_string(&mut env, binding_json)?;
        let binding = serde_json::from_str(&binding_json)
            .map_err(|_| "Android input binding is invalid".to_owned())?;
        let mut action_json = Zeroizing::new(read_string(&mut env, action_json)?);
        let action = serde_json::from_str(&action_json)
            .map_err(|_| "Android input action is invalid".to_owned())?;
        action_json.zeroize();
        get_session(handle)?.send_native_input(&binding, action)
    })();
    if let Err(error) = result {
        throw(&mut env, &error);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeReleaseInput(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    binding_json: JString<'_>,
) {
    let result = (|| {
        let binding_json = read_string(&mut env, binding_json)?;
        let binding = serde_json::from_str(&binding_json)
            .map_err(|_| "Android input binding is invalid".to_owned())?;
        get_session(handle)?.release_native_input(&binding)
    })();
    if let Err(error) = result {
        throw(&mut env, &error);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeVp8EncoderCreate(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    width: jint,
    height: jint,
    fps: jint,
    bitrate_kbps: jint,
) -> jlong {
    let result = (|| {
        let width = u32::try_from(width).map_err(|_| "invalid VP8 width".to_owned())?;
        let height = u32::try_from(height).map_err(|_| "invalid VP8 height".to_owned())?;
        let pixels = u64::from(width) * u64::from(height);
        if width > 8192 || height > 8192 || pixels * 4 > 64 * 1024 * 1024 {
            return Err("VP8 dimensions exceed the Android frame budget".to_owned());
        }
        let config = VideoConfig {
            width,
            height,
            fps: u32::try_from(fps).map_err(|_| "invalid VP8 frame rate".to_owned())?,
            bitrate_kbps: u32::try_from(bitrate_kbps)
                .map_err(|_| "invalid VP8 bitrate".to_owned())?,
        };
        let encoder = Vp8Encoder::new(config).map_err(|error| error.to_string())?;
        let frame_bytes = usize::try_from(pixels * 4)
            .map_err(|_| "VP8 dimensions exceed the Android frame budget".to_owned())?;
        let id = NEXT_VIDEO_ENCODER.fetch_add(1, Ordering::Relaxed);
        if id <= 0 {
            return Err("Android VP8 encoder handle space is exhausted".to_owned());
        }
        let mut encoders = video_encoders()
            .lock()
            .map_err(|_| "Android VP8 encoder registry is unavailable".to_owned())?;
        if encoders.len() >= MAX_VIDEO_ENCODERS {
            return Err("Android VP8 encoder capacity is exhausted".to_owned());
        }
        encoders.insert(
            id,
            VideoEncoderContext {
                encoder,
                frame_bytes,
            },
        );
        Ok(id)
    })();
    match result {
        Ok(handle) => handle,
        Err(error) => {
            throw(&mut env, &error);
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeVp8Encode(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    frame: JByteArray<'_>,
    pts_90khz: jlong,
    force_keyframe: jboolean,
) -> jobject {
    let result = (|| {
        if handle <= 0 || pts_90khz < 0 {
            return Err("invalid Android VP8 encoder handle or timestamp".to_owned());
        }
        let encoded = {
            let mut encoders = video_encoders()
                .lock()
                .map_err(|_| "Android VP8 encoder registry is unavailable".to_owned())?;
            let context = encoders
                .get_mut(&handle)
                .ok_or_else(|| "Android VP8 encoder handle is invalid".to_owned())?;
            let length = env
                .get_array_length(&frame)
                .map_err(|_| "Android screen frame is unavailable".to_owned())?;
            if usize::try_from(length).ok() != Some(context.frame_bytes) {
                return Err("Android screen frame does not match VP8 geometry".to_owned());
            }
            let mut frame = Zeroizing::new(
                env.convert_byte_array(&frame)
                    .map_err(|_| "Android screen frame is unavailable".to_owned())?,
            );
            let encoded = context
                .encoder
                .encode(&frame, pts_90khz as u64, force_keyframe != 0)
                .map_err(|error| error.to_string())?;
            frame.fill(0);
            encoded
        };
        encoded_video_object(&mut env, encoded)
    })();
    match result {
        Ok(object) => object.into_raw(),
        Err(error) => {
            throw(&mut env, &error);
            JObject::null().into_raw()
        }
    }
}

fn encoded_video_object<'local>(
    env: &mut JNIEnv<'local>,
    mut frame: EncodedVideo,
) -> Result<JObject<'local>, String> {
    let pts_90khz = jlong::try_from(frame.pts_90khz)
        .map_err(|_| "Android VP8 timestamp is invalid".to_owned())?;
    let keyframe = u8::from(frame.keyframe);
    let mut bytes = Zeroizing::new(std::mem::take(&mut frame.data));
    let object = env.with_local_frame_returning_local(3, |env| {
        let class = env.find_class("com/zhanry/nestlink/NativeEncodedVideoFrame")?;
        let data = env.byte_array_from_slice(&bytes)?;
        bytes.fill(0);
        env.new_object(
            class,
            "(JZ[B)V",
            &[
                JValue::Long(pts_90khz),
                JValue::Bool(keyframe),
                JValue::Object(&data),
            ],
        )
    });
    object.map_err(|_| "Android VP8 result could not be created".to_owned())
}

fn decoded_video_object<'local>(
    env: &mut JNIEnv<'local>,
    mut frame: nestlink_app_core::DecodedVideo,
) -> Result<JObject<'local>, String> {
    let mut pixels = Zeroizing::new(std::mem::take(&mut frame.pixels));
    let pixel_count = u64::from(frame.width) * u64::from(frame.height);
    let frame_bytes = pixel_count
        .checked_mul(4)
        .filter(|bytes| {
            frame.width > 0
                && frame.height > 0
                && frame.width <= 8192
                && frame.height <= 8192
                && *bytes <= MAX_DECODED_VIDEO_BYTES
        })
        .and_then(|bytes| usize::try_from(bytes).ok())
        .ok_or_else(|| "decoded Android video dimensions exceed the frame budget".to_owned())?;
    if pixels.len() != frame_bytes {
        return Err("decoded Android video pixels do not match the frame geometry".to_owned());
    }
    let connection_generation = jlong::try_from(frame.epoch.connection)
        .map_err(|_| "decoded Android video connection generation is invalid".to_owned())?;
    let layout_epoch = jlong::try_from(frame.epoch.layout)
        .map_err(|_| "decoded Android video layout epoch is invalid".to_owned())?;
    let source = jint::try_from(frame.source)
        .map_err(|_| "decoded Android video source is invalid".to_owned())?;
    let sequence = jlong::try_from(frame.sequence)
        .map_err(|_| "decoded Android video sequence is invalid".to_owned())?;
    let pts_90khz = jlong::try_from(frame.pts_90khz)
        .map_err(|_| "decoded Android video timestamp is invalid".to_owned())?;
    let width = jint::try_from(frame.width)
        .map_err(|_| "decoded Android video width is invalid".to_owned())?;
    let height = jint::try_from(frame.height)
        .map_err(|_| "decoded Android video height is invalid".to_owned())?;
    let object = env.with_local_frame_returning_local(3, |env| {
        let class = env.find_class("com/zhanry/nestlink/NativeDecodedVideoFrame")?;
        let data = env.byte_array_from_slice(&pixels)?;
        env.new_object(
            class,
            "(JJIJJII[B)V",
            &[
                JValue::Long(connection_generation),
                JValue::Long(layout_epoch),
                JValue::Int(source),
                JValue::Long(sequence),
                JValue::Long(pts_90khz),
                JValue::Int(width),
                JValue::Int(height),
                JValue::Object(&data),
            ],
        )
    });
    let object =
        object.map_err(|_| "Android decoded video result could not be created".to_owned())?;
    pixels.fill(0);
    Ok(object)
}

const MAX_VIDEO_ENCODERS: usize = 2;
const MAX_DECODED_VIDEO_BYTES: u64 = 64 * 1024 * 1024;

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeVp8EncoderDestroy(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) {
    let result = (|| {
        let mut encoders = video_encoders()
            .lock()
            .map_err(|_| "Android VP8 encoder registry is unavailable".to_owned())?;
        if encoders.remove(&handle).is_none() {
            return Err("Android VP8 encoder handle is invalid".to_owned());
        }
        Ok(())
    })();
    if let Err(error) = result {
        throw(&mut env, &error);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeRevokeDevice(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    device_id: JString<'_>,
) {
    let result = (|| {
        let device_id = read_string(&mut env, device_id)?;
        get_session(handle)?.revoke_device(device_id)
    })();
    if let Err(error) = result {
        throw(&mut env, &error);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeClipboardStatus(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jobject {
    let result = get_session(handle).and_then(|session| session.clipboard_status_json());
    nullable_java_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeClipboardSetDirections(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    binding_json: JString<'_>,
    read: jboolean,
    write: jboolean,
    endpoint: JObject<'_>,
) -> jobject {
    let result = (|| {
        let binding = read_clipboard_binding(read_string(&mut env, binding_json)?)?;
        let factory = if endpoint.is_null() {
            None
        } else {
            let vm = env
                .get_java_vm()
                .map_err(|_| "clipboard_platform_unavailable".to_owned())?;
            let endpoint = env
                .new_global_ref(endpoint)
                .map_err(|_| "clipboard_platform_unavailable".to_owned())?;
            Some(
                Arc::new(crate::platform_clipboard::AndroidClipboardFactory::new(
                    vm,
                    endpoint,
                    binding.clone(),
                )) as Arc<dyn nestlink_app_core::NativeClipboardPlatformFactory>,
            )
        };
        get_session(handle)?.clipboard_set_directions(&binding, read != 0, write != 0, factory)
    })();
    java_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeClipboardAction(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    binding_json: JString<'_>,
    send_local: jboolean,
) -> jobject {
    let result = (|| {
        let binding = read_clipboard_binding(read_string(&mut env, binding_json)?)?;
        get_session(handle)?.clipboard_action(&binding, send_local != 0)
    })();
    java_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeClipboardPlatformAllowed(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    binding_json: JString<'_>,
    read: jboolean,
) -> jboolean {
    let allowed: Result<bool, String> = (|| {
        let binding = read_clipboard_binding(read_string(&mut env, binding_json)?)?;
        Ok(get_session(handle)?.clipboard_platform_allowed(&binding, read != 0))
    })();
    u8::from(allowed.unwrap_or(false))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeLogout(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) {
    let result = get_session(handle).and_then(|session| session.logout());
    if let Err(error) = result {
        throw(&mut env, &error);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeClose(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) {
    let result: Result<(), String> = (|| {
        let session = match get_session(handle) {
            Ok(session) => session,
            Err(error) if handle > 0 && error == "Android SDK session has ended" => return Ok(()),
            Err(error) => return Err(error),
        };
        session.shutdown()?;
        match handles().remove(handle) {
            Ok(_) => {}
            Err(error) if error == "Android SDK session has ended" => {}
            Err(error) => return Err(error),
        }
        Ok(())
    })();
    if let Err(error) = result {
        throw(&mut env, &error);
    }
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeConfigureHostFileArea(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    private_area: JString<'_>,
) {
    let result = (|| {
        let area = read_string(&mut env, private_area)?;
        get_session(handle)?.configure_host_file_area(area.into())
    })();
    if let Err(error) = result {
        throw(&mut env, &error);
    }
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeHostFilesAttach(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    identity_json: JString<'_>,
) {
    let result = (|| {
        let identity = read_file_identity(read_string(&mut env, identity_json)?)?;
        get_session(handle)?.attach_host_files(&identity)
    })();
    if let Err(error) = result {
        throw(&mut env, &error);
    }
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeHostFilesStatus(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    identity_json: JString<'_>,
) -> jobject {
    let result = (|| {
        let identity = read_file_identity(read_string(&mut env, identity_json)?)?;
        get_session(handle)?.host_files_json(&identity)
    })();
    java_string(&mut env, result)
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeHostFileShare(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    identity_json: JString<'_>,
    display_name: JString<'_>,
    source_fd: jint,
) -> jobject {
    let result = (|| {
        let source = crate::file_transfer::take_detached_fd(source_fd)
            .map_err(|_| "selected Android host document is unavailable".to_owned())?;
        let identity = read_file_identity(read_string(&mut env, identity_json)?)?;
        let name = read_string(&mut env, display_name)?;
        get_session(handle)?.share_host_file(&identity, name, source)
    })();
    java_string(&mut env, result)
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeHostFileApproveReceive(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    identity_json: JString<'_>,
    approved: jboolean,
) {
    let result = (|| {
        let identity = read_file_identity(read_string(&mut env, identity_json)?)?;
        get_session(handle)?.approve_host_receive(&identity, approved != 0)
    })();
    if let Err(error) = result {
        throw(&mut env, &error);
    }
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeHostFileDiscard(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    identity_json: JString<'_>,
    artifact_id: JString<'_>,
) {
    let result = (|| {
        let identity = read_file_identity(read_string(&mut env, identity_json)?)?;
        let id = read_string(&mut env, artifact_id)?;
        get_session(handle)?.discard_host_file(&identity, &id)
    })();
    if let Err(error) = result {
        throw(&mut env, &error);
    }
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeHostFileExport(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    identity_json: JString<'_>,
    artifact_id: JString<'_>,
    destination_fd: jint,
) -> jobject {
    let result = (|| {
        let destination = crate::file_transfer::take_detached_fd(destination_fd)
            .map_err(|_| "Android host export target is unavailable".to_owned())?;
        let cleanup_owner = destination.try_clone().map_err(|error| {
            crate::file_transfer::export_start_error(
                format!(
                    "Android host export cleanup owner could not be retained ({:?})",
                    error.kind()
                ),
                crate::file_transfer::clear_saf_destination(&destination),
            )
        })?;
        let result = (|| {
            let identity = read_file_identity(read_string(&mut env, identity_json)?)?;
            let id = read_string(&mut env, artifact_id)?;
            get_session(handle)?.export_host_file(&identity, &id, destination)
        })();
        result.map_err(|error| {
            if error.contains("SAF destination was cleared")
                || error.contains("SAF destination cleanup could not be confirmed")
            {
                error
            } else {
                crate::file_transfer::export_start_error(
                    error,
                    crate::file_transfer::clear_saf_destination(&cleanup_owner),
                )
            }
        })
    })();
    java_string(&mut env, result)
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeHostFileExportCancel(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    identity_json: JString<'_>,
    export_id: JString<'_>,
) {
    let result = (|| {
        let identity = read_file_identity(read_string(&mut env, identity_json)?)?;
        let id = read_string(&mut env, export_id)?;
        get_session(handle)?.cancel_host_export(&identity, &id)
    })();
    if let Err(error) = result {
        throw(&mut env, &error);
    }
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeFileSessionIdentity(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jobject {
    let result = get_session(handle).and_then(|session| session.native_file_identity_json());
    nullable_java_string(&mut env, result)
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeFileRoots(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    identity_json: JString<'_>,
    write: jboolean,
) -> jobject {
    let result = (|| {
        let identity = read_file_identity(read_string(&mut env, identity_json)?)?;
        get_session(handle)?.native_file_roots_json(&identity, write != 0)
    })();
    java_string(&mut env, result)
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeFileBrowseBegin(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    identity_json: JString<'_>,
    root_id: JString<'_>,
    directory: JString<'_>,
) -> jobject {
    let result = (|| {
        let identity = read_file_identity(read_string(&mut env, identity_json)?)?;
        let root_id = read_string(&mut env, root_id)?;
        let directory = if directory.is_null() {
            None
        } else {
            Some(read_string(&mut env, directory)?)
        };
        get_session(handle)?.native_file_browse_begin_json(
            &identity,
            &root_id,
            directory.as_deref(),
        )
    })();
    java_string(&mut env, result)
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeFileBrowseNext(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    identity_json: JString<'_>,
    browse_id: JString<'_>,
) -> jobject {
    let result = (|| {
        let identity = read_file_identity(read_string(&mut env, identity_json)?)?;
        let browse_id = read_string(&mut env, browse_id)?;
        get_session(handle)?.native_file_browse_next_json(&identity, &browse_id)
    })();
    nullable_java_string(&mut env, result)
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeFileBrowseCancel(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    identity_json: JString<'_>,
    browse_id: JString<'_>,
) {
    let result = (|| {
        let identity = read_file_identity(read_string(&mut env, identity_json)?)?;
        let browse_id = read_string(&mut env, browse_id)?;
        get_session(handle)?.native_file_browse_cancel(&identity, &browse_id)
    })();
    if let Err(error) = result {
        throw(&mut env, &error);
    }
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeFileDownload(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    identity_json: JString<'_>,
    root_id: JString<'_>,
    relative_path: JString<'_>,
) -> jobject {
    let result = (|| {
        let identity = read_file_identity(read_string(&mut env, identity_json)?)?;
        let root_id = read_string(&mut env, root_id)?;
        let relative_path = read_string(&mut env, relative_path)?;
        get_session(handle)?.native_file_download(&identity, &root_id, &relative_path)
    })();
    java_string(&mut env, result)
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeFileUpload(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    identity_json: JString<'_>,
    root_id: JString<'_>,
    relative_path: JString<'_>,
    display_name: JString<'_>,
    source_fd: jint,
) -> jobject {
    let result = (|| {
        // Take ownership before parsing any other arguments so every detached
        // picker descriptor is closed on every success and error path.
        let source = crate::file_transfer::take_detached_fd(source_fd)
            .map_err(|_| "Android selected document is not available".to_owned())?;
        let identity = read_file_identity(read_string(&mut env, identity_json)?)?;
        let root_id = read_string(&mut env, root_id)?;
        let relative_path = read_string(&mut env, relative_path)?;
        let display_name = read_string(&mut env, display_name)?;
        get_session(handle)?.native_file_upload(
            &identity,
            &root_id,
            &relative_path,
            &display_name,
            source,
        )
    })();
    java_string(&mut env, result)
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeFileTaskStatus(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    identity_json: JString<'_>,
    task_id: JString<'_>,
) -> jobject {
    let result = (|| {
        let identity = read_file_identity(read_string(&mut env, identity_json)?)?;
        let task_id = read_string(&mut env, task_id)?;
        get_session(handle)?.native_file_task_json(&identity, &task_id)
    })();
    java_string(&mut env, result)
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeFileTaskControl(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    identity_json: JString<'_>,
    task_id: JString<'_>,
    action: jint,
) {
    let result = (|| {
        let identity = read_file_identity(read_string(&mut env, identity_json)?)?;
        let task_id = read_string(&mut env, task_id)?;
        let action = match action {
            0 => nestlink_app_core::NativeFileTaskAction::Pause,
            1 => nestlink_app_core::NativeFileTaskAction::Resume,
            2 => nestlink_app_core::NativeFileTaskAction::Cancel,
            _ => return Err("invalid Android file task action".to_owned()),
        };
        get_session(handle)?.native_file_task_control(&identity, &task_id, action)
    })();
    if let Err(error) = result {
        throw(&mut env, &error);
    }
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeFileDownloadDiscard(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    identity_json: JString<'_>,
    task_id: JString<'_>,
) {
    let result = (|| {
        let identity = read_file_identity(read_string(&mut env, identity_json)?)?;
        let task_id = read_string(&mut env, task_id)?;
        get_session(handle)?.native_file_download_discard(&identity, &task_id)
    })();
    if let Err(error) = result {
        throw(&mut env, &error);
    }
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeConfigureFileDownloadArea(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    private_area: JString<'_>,
) {
    let result = (|| {
        let private_area = read_string(&mut env, private_area)?;
        get_session(handle)?.set_native_file_download_area(private_area.into())
    })();
    if let Err(error) = result {
        throw(&mut env, &error);
    }
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeFileExport(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    identity_json: JString<'_>,
    task_id: JString<'_>,
    destination_fd: jint,
) -> jobject {
    let result = (|| {
        let destination = crate::file_transfer::take_detached_fd(destination_fd)
            .map_err(|_| "Android export destination is not available".to_owned())?;
        let cleanup_destination = match destination.try_clone() {
            Ok(destination) => destination,
            Err(error) => {
                return Err(crate::file_transfer::export_start_error(
                    format!(
                        "Android SAF cleanup owner could not be duplicated ({:?})",
                        error.kind()
                    ),
                    crate::file_transfer::clear_saf_destination(&destination),
                ));
            }
        };
        let operation = (|| {
            let identity = read_file_identity(read_string(&mut env, identity_json)?)?;
            let task_id = read_string(&mut env, task_id)?;
            get_session(handle)?.native_file_export(&identity, &task_id, destination)
        })();
        match operation {
            Ok(value) => Ok(value),
            Err(error)
                if error.contains("SAF destination was cleared")
                    || error.contains("SAF destination cleanup could not be confirmed") =>
            {
                Err(error)
            }
            Err(error) => {
                let cleanup = crate::file_transfer::clear_saf_destination(&cleanup_destination);
                Err(crate::file_transfer::export_start_error(error, cleanup))
            }
        }
    })();
    java_string(&mut env, result)
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeFileExportStatus(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    identity_json: JString<'_>,
    export_id: JString<'_>,
) -> jobject {
    let result = (|| {
        let identity = read_file_identity(read_string(&mut env, identity_json)?)?;
        let export_id = read_string(&mut env, export_id)?;
        get_session(handle)?.native_file_export_status(&identity, &export_id)
    })();
    java_string(&mut env, result)
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeFileExportCancel(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    identity_json: JString<'_>,
    export_id: JString<'_>,
) {
    let result = (|| {
        let identity = read_file_identity(read_string(&mut env, identity_json)?)?;
        let export_id = read_string(&mut env, export_id)?;
        get_session(handle)?.native_file_export_cancel(&identity, &export_id)
    })();
    if let Err(error) = result {
        throw(&mut env, &error);
    }
}

#[cfg(test)]
mod binding_tests {
    use super::{read_clipboard_binding, read_file_identity};
    use serde_json::json;

    #[test]
    fn file_identity_parser_preserves_generations_and_rejects_incomplete_or_oversized_input()
    -> Result<(), String> {
        let valid = json!({
            "binding": {"request_id": "request", "connection_generation": 17},
            "core_generation": 23,
        });
        let identity = read_file_identity(valid.to_string())?;
        assert_eq!(identity.binding.request_id, "request");
        assert_eq!(identity.binding.connection_generation, 17);
        assert_eq!(identity.core_generation, 23);

        for field in ["request_id", "connection_generation"] {
            let mut incomplete = valid.clone();
            incomplete["binding"][field] = if field == "request_id" {
                json!("")
            } else {
                json!(0)
            };
            assert!(read_file_identity(incomplete.to_string()).is_err());
        }
        let mut incomplete = valid.clone();
        incomplete["core_generation"] = json!(0);
        assert!(read_file_identity(incomplete.to_string()).is_err());
        let mut oversized = valid.clone();
        oversized["binding"]["request_id"] = json!("x".repeat(4_096));
        assert!(read_file_identity(oversized.to_string()).is_err());
        let mut extra = valid;
        extra["unexpected"] = json!(true);
        assert!(read_file_identity(extra.to_string()).is_err());
        assert!(read_file_identity("invalid json".to_owned()).is_err());
        Ok(())
    }

    #[test]
    fn clipboard_binding_parser_preserves_generations_and_rejects_invalid_identity()
    -> Result<(), String> {
        let valid = json!({
            "request_id": "request",
            "connection_generation": 17,
            "core_generation": 23,
        });
        let binding = read_clipboard_binding(valid.to_string())?;
        assert_eq!(binding.request_id, "request");
        assert_eq!(binding.connection_generation, 17);
        assert_eq!(binding.core_generation, 23);
        for field in ["request_id", "connection_generation", "core_generation"] {
            let mut incomplete = valid.clone();
            incomplete[field] = if field == "request_id" {
                json!("")
            } else {
                json!(0)
            };
            assert!(read_clipboard_binding(incomplete.to_string()).is_err());
        }
        for length in [129, 4_096] {
            let mut oversized = valid.clone();
            oversized["request_id"] = json!("x".repeat(length));
            assert!(read_clipboard_binding(oversized.to_string()).is_err());
        }
        assert!(read_clipboard_binding("invalid json".to_owned()).is_err());
        Ok(())
    }
}
