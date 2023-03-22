use jni::objects::JObject;
use jni::sys::{jbyteArray, jobjectArray};
use jni::JNIEnv;

use crate::conversions::{
    byte_array_from_java, byte_array_to_java, java_byte_array_to_jubjub_eddsa_sig,
    java_byte_array_to_jubjub_private_key, java_byte_array_to_jubjub_public_key, return_or_throw,
};
use eddsa::{sign, verify};
use group::{Group, GroupEncoding};
use jubjub::{Scalar, SubgroupPoint};

mod conversions;

#[no_mangle]
pub extern "system" fn Java_io_iohk_sidechains_jubjub_JubjubJniBindings_derivePublicKey(
    env: JNIEnv,
    _object: JObject,
    private_key: jbyteArray,
) -> jbyteArray {
    let result = java_byte_array_to_jubjub_private_key(env, private_key).and_then(|prv_key| {
        let g = SubgroupPoint::generator();
        let pub_key = g * prv_key;
        byte_array_to_java(env, &pub_key.to_bytes().to_vec())
    });

    return_or_throw(env, result)
}

#[no_mangle]
pub extern "system" fn Java_io_iohk_sidechains_jubjub_JubjubJniBindings_sign(
    env: JNIEnv,
    _object: JObject,
    msg: jbyteArray,
    prv_key: jbyteArray,
) -> jbyteArray {
    let result = byte_array_from_java(env, msg)
        .and_then(|msg| {
            java_byte_array_to_jubjub_private_key(env, prv_key).map(|prv_key| {
                let signature: (SubgroupPoint, Scalar) = sign(&msg, prv_key);
                let mut r_bytes = signature.0.to_bytes().to_vec();
                let mut s_bytes = signature.1.to_bytes().to_vec();
                r_bytes.append(&mut s_bytes);
                r_bytes
            })
        })
        .and_then(|native| byte_array_to_java(env, &native));

    return_or_throw(env, result)
}

#[no_mangle]
pub extern "system" fn Java_io_iohk_sidechains_jubjub_JubjubJniBindings_verify(
    env: JNIEnv,
    _object: JObject,
    msg: jbyteArray,
    sig: jbyteArray,
    pub_key: jbyteArray,
) -> bool {
    let result = byte_array_from_java(env, msg).and_then(|msg| {
        java_byte_array_to_jubjub_public_key(env, pub_key).and_then(|pub_key| {
            java_byte_array_to_jubjub_eddsa_sig(env, sig)
                .map(|sig| verify(sig, pub_key, &msg).is_ok())
        })
    });

    return_or_throw(env, result)
}

#[no_mangle]
pub extern "system" fn Java_io_iohk_sidechains_jubjub_JubjubJniBindings_createATMSProof(
    env: JNIEnv,
    _object: JObject,
    data: jbyteArray,
    _signatures: jobjectArray,
    _keys: jobjectArray,
) -> jbyteArray {
    let result: Result<jbyteArray, String> =
        byte_array_from_java(env, data).and_then(|native| byte_array_to_java(env, &native));

    return_or_throw(env, result)
}
