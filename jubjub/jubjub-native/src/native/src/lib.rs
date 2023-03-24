use eddsa::{sign, verify, EdDsaSignature};
use group::{Group, GroupEncoding};
use jni::objects::JObject;
use jni::sys::{jbyteArray, jobjectArray};
use jni::JNIEnv;
use jubjub::{Scalar, SubgroupPoint};
use std::convert::TryInto;

type PrivateKey = Scalar;
type PublicKey = SubgroupPoint;

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
                let signature: EdDsaSignature = sign(&msg, prv_key);
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

/// Private functions

fn byte_array_from_java(env: JNIEnv, data: jbyteArray) -> Result<Vec<u8>, String> {
    return env
        .convert_byte_array(data)
        .map_err(|error| format!("{}", error));
}

fn byte_array_to_java(env: JNIEnv, data: &Vec<u8>) -> Result<jbyteArray, String> {
    return env
        .byte_array_from_slice(data)
        .map_err(|error| format!("{}", error));
}

// Converts 64 bytes array into jubjub private key bytes
fn java_byte_array_to_jubjub_private_key(
    env: JNIEnv,
    bytes: jbyteArray,
) -> Result<PrivateKey, String> {
    byte_array_from_java(env, bytes).and_then(|bytes| {
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| String::from("private key length is invalid"))
            .map(|s| PrivateKey::from_bytes_wide(s))
    })
}

// Converts 32 bytes array into jubjub private key bytes
fn java_byte_array_to_jubjub_public_key(
    env: JNIEnv,
    bytes: jbyteArray,
) -> Result<PublicKey, String> {
    byte_array_from_java(env, bytes).and_then(|bytes| {
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| String::from("public key length is invalid"))
            .and_then(|s| {
                let ct_opt = PublicKey::from_bytes(s);
                if ct_opt.is_some().unwrap_u8() == 1 {
                    Ok(ct_opt.unwrap())
                } else {
                    Err(String::from("public key is invalid"))
                }
            })
    })
}

// Converts 64 bytes array into jubjub EdDsaSignature
fn java_byte_array_to_jubjub_eddsa_sig(
    env: JNIEnv,
    bytes: jbyteArray,
) -> Result<EdDsaSignature, String> {
    byte_array_from_java(env, bytes).and_then(|bytes| {
        let slice: Result<[u8; 64], String> = bytes
            .as_slice()
            .try_into()
            .map_err(|_| String::from("EdDSA signature length is invalid"));
        slice.and_then(|s| {
            let mut r_bytes: [u8; 32] = [0u8; 32];
            r_bytes.copy_from_slice(&s[0..32]);
            let r_ct_opt = SubgroupPoint::from_bytes(&r_bytes);

            let mut s_bytes: [u8; 32] = [0u8; 32];
            s_bytes.copy_from_slice(&s[32..64]);
            let s_ct_opt = Scalar::from_bytes(&s_bytes);

            if (s_ct_opt.is_some().unwrap_u8() == 1) && (r_ct_opt.is_some().unwrap_u8() == 1) {
                Ok((r_ct_opt.unwrap(), s_ct_opt.unwrap()))
            } else {
                Err(String::from("EdDSA signature is invalid"))
            }
        })
    })
}

fn return_or_throw<T, U: std::fmt::Display>(env: JNIEnv, maybe_value: Result<T, U>) -> T {
    match maybe_value {
        Ok(value) => value,
        Err(error) => {
            let msg = format!("{}", error);
            let _ = env.throw_new("java/lang/Exception", msg);
            return unsafe { ::std::mem::zeroed() };
        }
    }
}
