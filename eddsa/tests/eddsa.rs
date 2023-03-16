use eddsa::sign;
use eddsa::verify;
use group::ff::Field;
use group::Group;
use jubjub::*;
use rand_core::SeedableRng;
use rand_xorshift::XorShiftRng;

pub fn new_rng() -> XorShiftRng {
    XorShiftRng::from_seed([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
}

#[test]
fn should_create_valid_signature() {
    let mut rng = new_rng();
    let g = SubgroupPoint::generator();

    let prv_key = Scalar::random(&mut rng);
    let pub_key = g * prv_key;

    let msg = "Alice has a cat".as_bytes().to_vec();
    let sig = sign(&msg, prv_key);
    let result = verify(sig, pub_key, &msg);
    assert!(result.is_ok());
}

#[test]
fn invalid_signature_should_not_pass() {
    let mut rng = new_rng();
    let g = SubgroupPoint::generator();

    let prv_key = Scalar::random(&mut rng);
    let pub_key = g * prv_key;

    let msg = "Alice has a cat".as_bytes().to_vec();
    let sig = sign(&msg, prv_key);
    let result = verify(sig, pub_key, &"Bob has a cat".as_bytes().to_vec());
    assert!(result.is_err());
}
