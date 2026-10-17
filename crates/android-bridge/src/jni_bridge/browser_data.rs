#[cfg(target_os = "android")]
use super::*;
use nestlink_app_core::BrowserHostBinding;

fn read_browser_binding(json: String) -> Result<BrowserHostBinding, String> {
    if json.len() > 4_096 {
        return Err("stale_browser_binding".into());
    }
    let binding: BrowserHostBinding =
        serde_json::from_str(&json).map_err(|_| "stale_browser_binding".to_owned())?;
    if [
        &binding.request_id,
        &binding.session_id,
        &binding.controller_device_id,
        &binding.host_device_id,
    ]
    .into_iter()
    .any(|value| !nestlink_protocol::valid_id(value))
        || binding.connection_generation == 0
    {
        return Err("stale_browser_binding".into());
    }
    Ok(binding)
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeBrowserHostDataStatus(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    binding_json: JString<'_>,
) -> jobject {
    let result = (|| {
        let binding = read_browser_binding(read_string(&mut env, binding_json)?)?;
        get_session(handle)?.browser_data_json(&binding)
    })();
    java_string(&mut env, result)
}
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeBrowserHostFilesStatus(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    binding_json: JString<'_>,
) -> jobject {
    let result = (|| {
        let binding = read_browser_binding(read_string(&mut env, binding_json)?)?;
        get_session(handle)?.browser_files_json(&binding)
    })();
    java_string(&mut env, result)
}
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeBrowserHostFileShare(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    binding_json: JString<'_>,
    grant_id: JString<'_>,
    display_name: JString<'_>,
    source_fd: jint,
) -> jobject {
    let result = (|| {
        // Adopt before parsing or lookup: every rejected detached descriptor closes.
        let source = crate::file_transfer::take_detached_fd(source_fd)
            .map_err(|_| "Android browser selected document is unavailable".to_owned())?;
        let binding = read_browser_binding(read_string(&mut env, binding_json)?)?;
        let grant = read_string(&mut env, grant_id)?;
        let name = read_string(&mut env, display_name)?;
        get_session(handle)?.browser_share_file(&binding, &grant, name, source)
    })();
    java_string(&mut env, result)
}
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeBrowserHostFileApproveReceive(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    binding_json: JString<'_>,
    approved: jboolean,
) {
    let result = (|| {
        let binding = read_browser_binding(read_string(&mut env, binding_json)?)?;
        get_session(handle)?.browser_approve_receive(&binding, approved != 0)
    })();
    if let Err(error) = result {
        throw(&mut env, &error);
    }
}
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeBrowserHostFileDiscard(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    binding_json: JString<'_>,
    artifact_id: JString<'_>,
) {
    let result = (|| {
        let binding = read_browser_binding(read_string(&mut env, binding_json)?)?;
        let id = read_string(&mut env, artifact_id)?;
        get_session(handle)?.browser_discard_file(&binding, &id)
    })();
    if let Err(error) = result {
        throw(&mut env, &error);
    }
}
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeBrowserHostFileExport(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    binding_json: JString<'_>,
    grant_id: JString<'_>,
    artifact_id: JString<'_>,
    destination_fd: jint,
) -> jobject {
    let result = (|| {
        let destination = crate::file_transfer::take_detached_fd(destination_fd)
            .map_err(|_| "Android browser export target is unavailable".to_owned())?;
        let cleanup_owner = destination.try_clone().map_err(|error| {
            crate::file_transfer::export_start_error(
                format!(
                    "Android browser export cleanup owner could not be retained ({:?})",
                    error.kind()
                ),
                crate::file_transfer::clear_saf_destination(&destination),
            )
        })?;
        let result = (|| {
            let binding = read_browser_binding(read_string(&mut env, binding_json)?)?;
            let grant = read_string(&mut env, grant_id)?;
            let id = read_string(&mut env, artifact_id)?;
            get_session(handle)?.browser_export_file(&binding, &grant, &id, destination)
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
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeBrowserHostFileExportCancel(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    binding_json: JString<'_>,
    export_id: JString<'_>,
) {
    let result = (|| {
        let binding = read_browser_binding(read_string(&mut env, binding_json)?)?;
        let id = read_string(&mut env, export_id)?;
        get_session(handle)?.browser_cancel_export(&binding, &id)
    })();
    if let Err(error) = result {
        throw(&mut env, &error);
    }
}
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeBrowserHostFileExportStatus(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    binding_json: JString<'_>,
    grant_id: JString<'_>,
) -> jobject {
    let result = (|| {
        let binding = read_browser_binding(read_string(&mut env, binding_json)?)?;
        let grant = read_string(&mut env, grant_id)?;
        get_session(handle)?.browser_export_status_json(&binding, &grant)
    })();
    java_string(&mut env, result)
}
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeBrowserClipboardSetDirections(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    binding_json: JString<'_>,
    read: jboolean,
    write: jboolean,
    endpoint: JObject<'_>,
) -> jobject {
    let result = (|| {
        let binding = read_browser_binding(read_string(&mut env, binding_json)?)?;
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
                crate::platform_clipboard::AndroidBrowserClipboardFactory::new(
                    vm,
                    endpoint,
                    binding.clone(),
                ),
            )
        };
        get_session(handle)?.browser_clipboard_set_directions(
            &binding,
            read != 0,
            write != 0,
            factory,
        )
    })();
    java_string(&mut env, result)
}
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeBrowserClipboardPlatformAllowed(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    binding_json: JString<'_>,
    read: jboolean,
) -> jboolean {
    let result = (|| -> Result<bool, String> {
        let binding = read_browser_binding(read_string(&mut env, binding_json)?)?;
        Ok(get_session(handle)?.browser_clipboard_platform_allowed(&binding, read != 0))
    })();
    u8::from(result.unwrap_or(false))
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeBrowserHostFilePlatformAllowed(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    binding_json: JString<'_>,
    write: jboolean,
) -> jboolean {
    let result = (|| -> Result<bool, String> {
        let binding = read_browser_binding(read_string(&mut env, binding_json)?)?;
        Ok(get_session(handle)?.browser_files_platform_allowed(&binding, write != 0))
    })();
    u8::from(result.unwrap_or(false))
}

#[cfg(test)]
mod tests {
    use super::read_browser_binding;
    #[test]
    fn browser_binding_is_full_and_never_a_native_alias() -> Result<(), Box<dyn std::error::Error>>
    {
        let valid = serde_json::json!({"request_id":"00000000-0000-0000-0000-000000000001", "session_id":"00000000-0000-0000-0000-000000000002", "controller_device_id":"00000000-0000-0000-0000-000000000003", "host_device_id":"00000000-0000-0000-0000-000000000004", "controller_key_sha256":vec![1_u8;32], "host_key_sha256":vec![2_u8;32], "permit_sha256":vec![3_u8;32], "connection_generation":8});
        let parsed = read_browser_binding(valid.to_string())?;
        assert_ne!(parsed.request_id, parsed.session_id);
        for field in [
            "request_id",
            "session_id",
            "controller_key_sha256",
            "host_key_sha256",
            "permit_sha256",
            "connection_generation",
        ] {
            let mut absent = valid.clone();
            absent
                .as_object_mut()
                .ok_or("object missing")?
                .remove(field);
            assert!(read_browser_binding(absent.to_string()).is_err());
        }
        assert!(read_browser_binding(serde_json::json!({"request_id":"outer-request", "connection_generation":8, "core_generation":9}).to_string()).is_err());
        let mut changed = valid.clone();
        changed["permit_sha256"][0] = 9.into();
        assert_ne!(parsed, read_browser_binding(changed.to_string())?);
        Ok(())
    }
}
