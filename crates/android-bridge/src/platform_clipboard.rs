//! Synchronous, bounded JNI calls owned by platform-clipboard's real worker.
#![cfg_attr(not(target_os = "android"), allow(dead_code))]
use jni::{
    JNIEnv, JavaVM,
    objects::{GlobalRef, JByteArray, JObject, JValue},
};
use nestlink_app_core::{
    BrowserHostBinding, NativeClipboardBinding, NativeClipboardPlatformFactory,
};
use nestlink_platform_clipboard::{
    AndroidClipboard, AndroidClipboardBridge, CLIPBOARD_TEXT_BYTES, ClipboardAuthority,
    ClipboardBinding, LocalClipboardApproval, NativeClipboard,
};
use std::{
    io,
    sync::{Arc, Mutex},
    time::Instant,
};
use zeroize::Zeroizing;

pub(crate) struct AndroidClipboardFactory {
    binding: NativeClipboardBinding,
    endpoint: Mutex<Option<AndroidJvmClipboard>>,
}

impl AndroidClipboardFactory {
    pub(crate) fn new(vm: JavaVM, endpoint: GlobalRef, binding: NativeClipboardBinding) -> Self {
        Self {
            endpoint: Mutex::new(Some(AndroidJvmClipboard {
                vm,
                endpoint,
                binding: ClipboardOwnerBinding::Native(binding.clone()),
            })),
            binding,
        }
    }
}

impl NativeClipboardPlatformFactory for AndroidClipboardFactory {
    fn open(
        &self,
        binding: ClipboardBinding,
        core_generation: u64,
        approval: LocalClipboardApproval,
        authority: Arc<dyn ClipboardAuthority>,
    ) -> io::Result<Box<dyn NativeClipboard>> {
        if binding.session_id != self.binding.request_id
            || binding.connection_generation != self.binding.connection_generation
            || core_generation != self.binding.core_generation
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Android clipboard binding changed",
            ));
        }
        let endpoint = self
            .endpoint
            .lock()
            .map_err(|_| io::Error::other("Android clipboard owner is unavailable"))?
            .take()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Android clipboard endpoint was already consumed",
                )
            })?;
        AndroidClipboard::open(binding, approval, authority, Box::new(endpoint))
            .map(|device| Box::new(device) as Box<dyn NativeClipboard>)
    }
}

enum ClipboardOwnerBinding {
    Native(NativeClipboardBinding),
    Browser(BrowserHostBinding),
}

/// One consumed local endpoint for the exact browser proof, never a native alias.
pub(crate) struct AndroidBrowserClipboardFactory {
    binding: BrowserHostBinding,
    endpoint: Mutex<Option<AndroidJvmClipboard>>,
}
impl AndroidBrowserClipboardFactory {
    pub(crate) fn new(vm: JavaVM, endpoint: GlobalRef, binding: BrowserHostBinding) -> Self {
        Self {
            endpoint: Mutex::new(Some(AndroidJvmClipboard {
                vm,
                endpoint,
                binding: ClipboardOwnerBinding::Browser(binding.clone()),
            })),
            binding,
        }
    }
    pub(crate) fn open(
        &self,
        binding: ClipboardBinding,
        approval: LocalClipboardApproval,
        authority: Arc<dyn ClipboardAuthority>,
    ) -> io::Result<Box<dyn NativeClipboard>> {
        if binding.session_id != self.binding.session_id
            || binding.connection_generation != self.binding.connection_generation
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Android browser clipboard proof changed",
            ));
        }
        let endpoint = self
            .endpoint
            .lock()
            .map_err(|_| io::Error::other("Android browser clipboard owner unavailable"))?
            .take()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Android browser clipboard endpoint was consumed",
                )
            })?;
        AndroidClipboard::open(binding, approval, authority, Box::new(endpoint))
            .map(|device| Box::new(device) as Box<dyn NativeClipboard>)
    }
}

struct AndroidJvmClipboard {
    vm: JavaVM,
    endpoint: GlobalRef,
    binding: ClipboardOwnerBinding,
}

impl AndroidJvmClipboard {
    fn jni<T>(
        &self,
        operation: impl FnOnce(&mut JNIEnv<'_>) -> jni::errors::Result<T>,
    ) -> io::Result<T> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|_| io::Error::other("Android clipboard JVM attachment failed"))?;
        let result = env.with_local_frame(16, operation);
        // Exception details can contain system clipboard content. Clear them
        // without describing or forwarding their messages to UI/status/logs.
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
        }
        result.map_err(|_| io::Error::other("Android clipboard endpoint invocation failed"))
    }

    fn budget(until: Instant) -> io::Result<i64> {
        let millis = until.saturating_duration_since(Instant::now()).as_millis();
        if millis == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Android clipboard deadline exhausted",
            ));
        }
        i64::try_from(millis).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Android clipboard budget is invalid",
            )
        })
    }
}

fn status(code: i32) -> io::Result<()> {
    let (kind, reason) = match code {
        0 => return Ok(()),
        1 => (
            io::ErrorKind::WouldBlock,
            "Android clipboard requires the resumed and focused app",
        ),
        2 => (
            io::ErrorKind::PermissionDenied,
            "Android clipboard session or local direction was revoked",
        ),
        3 => (
            io::ErrorKind::NotFound,
            "Android did not provide readable clipboard text",
        ),
        4 => (
            io::ErrorKind::Unsupported,
            "Android clipboard contains unsupported content",
        ),
        5 => (
            io::ErrorKind::InvalidData,
            "Android clipboard text exceeds its budget or is invalid",
        ),
        6 => (
            io::ErrorKind::PermissionDenied,
            "Android rejected clipboard access",
        ),
        7 => (
            io::ErrorKind::Other,
            "Android clipboard service is unavailable",
        ),
        8 => (
            io::ErrorKind::TimedOut,
            "Android clipboard operation deadline exhausted",
        ),
        9 => (
            io::ErrorKind::Other,
            "Android clipboard write outcome is unknown",
        ),
        _ => (
            io::ErrorKind::InvalidData,
            "Android clipboard returned an invalid outcome",
        ),
    };
    Err(io::Error::new(kind, reason))
}

impl AndroidClipboardBridge for AndroidJvmClipboard {
    fn check(&mut self, until: Instant) -> io::Result<()> {
        Self::budget(until)?;
        let code = self.jni(|env| {
            let bound = match &self.binding {
                ClipboardOwnerBinding::Native(binding) => {
                    let request = JObject::from(env.new_string(&binding.request_id)?);
                    let connection = i64::try_from(binding.connection_generation)
                        .map_err(|_| jni::errors::Error::NullPtr("clipboard generation"))?;
                    let core = i64::try_from(binding.core_generation)
                        .map_err(|_| jni::errors::Error::NullPtr("clipboard core generation"))?;
                    env.call_method(
                        self.endpoint.as_obj(),
                        "matchesBinding",
                        "(Ljava/lang/String;JJ)Z",
                        &[
                            JValue::Object(&request),
                            JValue::Long(connection),
                            JValue::Long(core),
                        ],
                    )?
                    .z()?
                }
                ClipboardOwnerBinding::Browser(binding) => {
                    let encoded = serde_json::to_string(binding)
                        .map_err(|_| jni::errors::Error::NullPtr("browser clipboard binding"))?;
                    let exact = JObject::from(env.new_string(encoded)?);
                    env.call_method(
                        self.endpoint.as_obj(),
                        "matchesBrowserBinding",
                        "(Ljava/lang/String;)Z",
                        &[JValue::Object(&exact)],
                    )?
                    .z()?
                }
            };
            if !bound {
                return Ok(2);
            }
            env.call_method(self.endpoint.as_obj(), "checkActive", "()I", &[])?
                .i()
        })?;
        status(code)?;
        Self::budget(until).map(|_| ())
    }

    fn read_text(&mut self, until: Instant) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
        let budget = Self::budget(until)?;
        let (code, bytes) = self.jni(|env| {
            let result = env
                .call_method(
                    self.endpoint.as_obj(),
                    "readText",
                    "(J)Lcom/zhanry/nestlink/NativeClipboardResult;",
                    &[JValue::Long(budget)],
                )?
                .l()?;
            let copied = (|| {
                let code = env.get_field(&result, "status", "I")?.i()?;
                let value = env.get_field(&result, "data", "[B")?.l()?;
                if value.is_null() {
                    return Ok((code, None));
                }
                let array = JByteArray::from(value);
                let length = env.get_array_length(&array)?;
                if length < 0 || length as usize > CLIPBOARD_TEXT_BYTES {
                    return Ok((5, None));
                }
                let bytes = Zeroizing::new(env.convert_byte_array(&array)?);
                Ok((code, Some(bytes)))
            })();
            if copied.is_err() && env.exception_check().unwrap_or(false) {
                let _ = env.exception_clear();
            }
            // The bounded Kotlin result clears its own array even if the
            // status, length, field lookup or native copy was rejected.
            env.call_method(&result, "clear", "()V", &[])?;
            copied
        })?;
        status(code)?;
        Self::budget(until)?;
        bytes.map(Some).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Android clipboard omitted its bounded text reply",
            )
        })
    }

    fn write_text(&mut self, text: &[u8], until: Instant) -> io::Result<()> {
        let budget = Self::budget(until)?;
        let code = self.jni(|env| {
            let bytes = env.byte_array_from_slice(text)?;
            let result = env
                .call_method(
                    self.endpoint.as_obj(),
                    "writeText",
                    "([BJ)I",
                    &[JValue::Object(bytes.as_ref()), JValue::Long(budget)],
                )
                .and_then(|value| value.i());
            if result.is_err() && env.exception_check().unwrap_or(false) {
                let _ = env.exception_clear();
            }
            env.set_byte_array_region(&bytes, 0, &vec![0; text.len()])?;
            result
        })?;
        status(code)?;
        Self::budget(until).map(|_| ())
    }

    fn close(&mut self, _until: Instant) -> io::Result<()> {
        self.jni(|env| {
            env.call_method(self.endpoint.as_obj(), "close", "()V", &[])
                .map(|_| ())
        })
    }
}
