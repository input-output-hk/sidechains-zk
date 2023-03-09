use group::ff::Field;
use group::Curve;
use group::Group;
use jubjub::Fq as BlsScalar;
use jubjub::*;
use poseidon::sponge;
use rand::thread_rng;
use sha2::Digest;
use sha2::Sha512;
use std::convert::TryInto;

pub type EdDsaSignature = (SubgroupPoint, Scalar);

#[allow(non_snake_case)]
pub fn sign(msg: &Vec<u8>, prv_key: Scalar) -> EdDsaSignature {
    let G = SubgroupPoint::generator();
    let pub_key = G * prv_key;

    let r = Scalar::random(&mut thread_rng());

    // R = r * G
    let R = G * r;

    //  h = hash(R + pubKey + msg) mod q
    let h = jubjub_scalar_from_bls(sponge::hash(&[
        ExtendedPoint::from(R).to_affine().get_u(),
        ExtendedPoint::from(pub_key).to_affine().get_u(),
        bytes_to_bls_scalar(msg),
    ]));

    // s = (r + h * privKey) mod q
    let s = r + (h * prv_key);
    (R, s)
}

#[allow(non_snake_case)]
pub fn verify(sig: EdDsaSignature, pub_key: SubgroupPoint, msg: &Vec<u8>) -> Result<(), ()> {
    let G = SubgroupPoint::generator();
    //  h = hash(R + pubKey + msg) mod q
    let h = jubjub_scalar_from_bls(sponge::hash(&[
        ExtendedPoint::from(sig.0).to_affine().get_u(),
        ExtendedPoint::from(pub_key).to_affine().get_u(),
        bytes_to_bls_scalar(msg),
    ]));

    // P1 = s * G
    let P1 = G * sig.1;
    // P2 = R + h * pubKey
    let P2 = sig.0 + (pub_key * h);
    // P1 == P2
    if P1.eq(&P2) {
        Ok(())
    } else {
        Err(())
    }
}

fn jubjub_scalar_from_bls(bls_scalar: BlsScalar) -> Scalar {
    Scalar::from_bytes_wide(
        &[bls_scalar.to_bytes(), [0; 32]]
            .concat()
            .try_into()
            .expect("BlsScalar represented with unexpected size. Assumed would have 32 bytes, and instead has {bls_scalar.to_bytes().len()}")
    )
}

fn bytes_to_bls_scalar(bytes: &Vec<u8>) -> BlsScalar {
    let hash_in = Sha512::digest(bytes);
    BlsScalar::from_bytes_wide(hash_in.as_slice().try_into().unwrap()) // The unwrap is safe, because the output of SHA512 has 64 bytes.
}
