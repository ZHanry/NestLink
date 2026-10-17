use super::{get_session, java_string, read_string};
use jni::{
    JNIEnv,
    objects::{JClass, JString},
    sys::{jlong, jobject},
};

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeServiceContext(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jobject {
    let result = (|| {
        let session = get_session(handle)?;
        session.service_context_json()
    })();
    java_string(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_zhanry_nestlink_NativeSdk_nativeServiceAction(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    request_json: JString<'_>,
) -> jobject {
    let result = (|| {
        // Reject a retired native owner before decoding user input.
        let session = get_session(handle)?;
        let request = read_string(&mut env, request_json)?;
        session.service_action_json(&request)
    })();
    java_string(&mut env, result)
}
