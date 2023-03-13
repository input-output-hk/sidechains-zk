use jni::JNIEnv;
use jni::objects::JObject;
use jni::sys::{jbyteArray, jobjectArray};

use crate::conversions::{byte_array_from_java, byte_array_to_java, return_or_throw};

mod conversions;


#[no_mangle]
pub extern "system" fn Java_io_iohk_sidechains_jubjub_JubjubJniBindings_createKey(
    env: JNIEnv,
    _object: JObject,
) -> jbyteArray {
    return env.new_byte_array(0).expect("failed to create an empty array");
}


#[no_mangle]
pub extern "system" fn Java_io_iohk_sidechains_jubjub_JubjubJniBindings_sign(
    env: JNIEnv,
    _object: JObject,
    data: jbyteArray,
    _key: jbyteArray,
) -> jbyteArray {
    let result: Result<jbyteArray, jni::errors::Error> =
        byte_array_from_java(env, data)
            .and_then(|native| byte_array_to_java(env, &native));

    return_or_throw(env, result)
}


#[no_mangle]
pub extern "system" fn Java_io_iohk_sidechains_jubjub_JubjubJniBindings_createProof(
    env: JNIEnv,
    _object: JObject,
    data: jbyteArray,
    _signatures: jobjectArray,
    _keys: jobjectArray,
) -> jbyteArray {
    let result: Result<jbyteArray, jni::errors::Error> =
        byte_array_from_java(env, data)
            .and_then(|native| byte_array_to_java(env, &native));

    return_or_throw(env, result)
}
