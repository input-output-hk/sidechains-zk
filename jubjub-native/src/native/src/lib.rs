use jni::JNIEnv;
use jni::objects::JObject;
use jni::sys::{jbyteArray, jobjectArray};

#[no_mangle]
pub extern "system" fn Java_io_iohk_sidechains_jubjub_JubjubJniBindings_createKey(
    env: JNIEnv,
    _object: JObject,
) -> jbyteArray {
    return env.new_byte_array(0).expect("failed to create an empty array");
}


#[no_mangle]
pub extern "system" fn Java_io_iohk_sidechains_jubjub_JubjubJniBindings_sign(
    _env: JNIEnv,
    _object: JObject,
    data: jbyteArray,
    _key: jbyteArray,
) -> jbyteArray {
    return data;
}


#[no_mangle]
pub extern "system" fn Java_io_iohk_sidechains_jubjub_JubjubJniBindings_createProof(
    _env: JNIEnv,
    _object: JObject,
    data: jbyteArray,
    _signatures: jobjectArray,
    _keys: jobjectArray,
) -> jbyteArray {
    return data;
}
