use super::{get_session, java_string, read_string};
use jni::{
    JNIEnv,
    objects::{JClass, JString},
    sys::{jlong, jobject},
};

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeConfigureNetworkArea(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    directory: JString<'_>,
) -> jobject {
    let result = (|| {
        let session = get_session(handle)?;
        let directory = read_string(&mut env, directory)?;
        session.configure_native_network_area(&directory)
    })();
    java_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeNetworkSettings(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jobject {
    java_string(
        &mut env,
        get_session(handle).and_then(|session| session.native_network_settings_json()),
    )
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeConfigureNetwork(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    expected_generation: jlong,
    expected_revision: jlong,
    settings: JString<'_>,
) -> jobject {
    let result = (|| {
        let session = get_session(handle)?;
        let expected_generation = u64::try_from(expected_generation)
            .map_err(|_| "The displayed network settings are no longer current".to_owned())?;
        let expected_revision = u64::try_from(expected_revision)
            .map_err(|_| "The displayed network settings are no longer current".to_owned())?;
        let settings = read_string(&mut env, settings)?;
        session.configure_native_network(expected_generation, expected_revision, &settings)
    })();
    java_string(&mut env, result)
}
