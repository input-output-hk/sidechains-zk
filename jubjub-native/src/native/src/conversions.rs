use jni::JNIEnv;
use jni::sys::jbyteArray;

pub fn byte_array_from_java(
    env: JNIEnv,
    data: jbyteArray,
) -> Result<Vec<u8>, jni::errors::Error> {
    return env.convert_byte_array(data);
}

pub fn byte_array_to_java(
    env: JNIEnv,
    data: &Vec<u8>,
) -> Result<jbyteArray, jni::errors::Error> {
    return env.byte_array_from_slice(data);
}

pub fn return_or_throw<T>(env: JNIEnv, maybe_value: Result<T, jni::errors::Error>) -> T {
    match maybe_value {
        Ok(value) => value,
        Err(error) => {
            let msg = format!("{}", error);
            let _ = env.throw_new("java/lang/Exception", msg);
            return unsafe { ::std::mem::zeroed() };
        }
    }
}