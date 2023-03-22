use group::GroupEncoding;
use jni::sys::jbyteArray;
use jni::JNIEnv;
use jubjub::{Scalar, SubgroupPoint};
use std::convert::TryInto;

pub fn byte_array_from_java(env: JNIEnv, data: jbyteArray) -> Result<Vec<u8>, String> {
    return env
        .convert_byte_array(data)
        .map_err(|error| format!("{}", error));
}

pub fn byte_array_to_java(env: JNIEnv, data: &Vec<u8>) -> Result<jbyteArray, String> {
    return env
        .byte_array_from_slice(data)
        .map_err(|error| format!("{}", error));
}

// Converts 64 bytes array into jubjub private key bytes
pub fn java_byte_array_to_jubjub_private_key(
    env: JNIEnv,
    bytes: jbyteArray,
) -> Result<Scalar, String> {
    byte_array_from_java(env, bytes).and_then(|bytes| {
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| String::from("private key length is invalid"))
            .map(|s| Scalar::from_bytes_wide(s))
    })
}

// Converts 32 bytes array into jubjub private key bytes
pub fn java_byte_array_to_jubjub_public_key(
    env: JNIEnv,
    bytes: jbyteArray,
) -> Result<SubgroupPoint, String> {
    byte_array_from_java(env, bytes).and_then(|bytes| {
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| String::from("public key length is invalid"))
            .and_then(|s| {
                let ct_opt = SubgroupPoint::from_bytes(s);
                if ct_opt.is_some().unwrap_u8() == 1 {
                    Ok(ct_opt.unwrap())
                } else {
                    Err(String::from("public key is invalid"))
                }
            })
    })
}

// Converts 64 bytes array into jubjub EdDsaSignature
pub fn java_byte_array_to_jubjub_eddsa_sig(
    env: JNIEnv,
    bytes: jbyteArray,
) -> Result<(SubgroupPoint, Scalar), String> {
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

pub fn return_or_throw<T, U: std::fmt::Display>(env: JNIEnv, maybe_value: Result<T, U>) -> T {
    match maybe_value {
        Ok(value) => value,
        Err(error) => {
            let msg = format!("{}", error);
            let _ = env.throw_new("java/lang/Exception", msg);
            return unsafe { ::std::mem::zeroed() };
        }
    }
}
