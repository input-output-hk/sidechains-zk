//! Primitive functionality of Schnorr signature.
//! - Key generation
//! - Signing
//! - Signature verification
//! - test
//!
//! Visit [Documentation][crate::signatures::primitive::documentation] for the
//! algorithm explanation.

use crate::rescue::{RescueParametersBls, RescueSponge};
use crate::signatures::schnorr::SchnorrSig;
use ff::Field;
use group::{Curve, Group};
use halo2curves::jubjub::{AffinePoint, Base, ExtendedPoint, Scalar, SubgroupPoint};
use halo2curves::CurveAffine;
use rand_core::{CryptoRng, RngCore};
use std::fmt::Error;
use std::ops::{Add, Mul};

#[derive(Debug)]
pub struct Schnorr;

fn generator() -> ExtendedPoint {
    ExtendedPoint::from(SubgroupPoint::generator())
}

impl Schnorr {
    /// Key generation for a Schnorr signer.
    /// Select a random `scalar` as the secret key of the signer. It is an element of the scalar
    /// field of `jubjub` curve.
    /// Compute the public key as an affine elliptic curve point. $sk \cdot G$.
    /// Return the key pair `(sk, pk)`.
    pub fn keygen<R: CryptoRng + RngCore>(rng: &mut R) -> (Scalar, AffinePoint) {
        let sk = Scalar::random(rng);
        let pk = generator().mul(sk).to_affine();

        (sk, pk)
    }

    // probabilistic function. We can make this deterministic using EdDSA instead.
    /// Schnorr signature generation.
    /// See Schnorr signature scheme [$sign$][crate::signatures::primitive::documentation#sign] algorithm.
    #[doc = include_str!("../../../docs/schnorr/primitive-sign.md")]
    pub fn sign<R: CryptoRng + RngCore>(
        key_pair: (Scalar, AffinePoint),
        msg: Base,
        rng: &mut R,
    ) -> SchnorrSig {
        let k = Scalar::random(rng);
        let announcement = generator().mul(k).to_affine();

        let input_hash = [
            *announcement.coordinates().unwrap().x(),
            *key_pair.1.coordinates().unwrap().x(),
            msg,
        ];

        let challenge = RescueSponge::<Base, RescueParametersBls>::hash(&input_hash, None);

        // we need to have some wide bytes to reduce the challenge.
        let mut wide_bytes = [0u8; 64];
        wide_bytes[..32].copy_from_slice(&challenge.to_bytes());
        let reduced_challenge = Scalar::from_bytes_wide(&wide_bytes);

        let response = k + reduced_challenge * key_pair.0;
        (announcement, response)
    }

    /// Schnorr verify signature.
    /// See Schnorr signature scheme [$verify$](crate::signatures::primitive::documentation#verify) algorithm.
    #[doc = include_str!("../../../docs/schnorr/primitive-verify.md")]
    pub fn verify(msg: Base, pk: AffinePoint, sig: SchnorrSig) -> Result<(), Error> {
        let input_hash = [
            *sig.0.coordinates().unwrap().x(),
            *pk.coordinates().unwrap().x(),
            msg,
        ];

        let challenge = RescueSponge::<Base, RescueParametersBls>::hash(&input_hash, None);

        // we need to have some wide bytes to reduce the challenge.
        let mut wide_bytes = [0u8; 64];
        wide_bytes[..32].copy_from_slice(&challenge.to_bytes());
        let reduced_challenge = Scalar::from_bytes_wide(&wide_bytes);

        if generator().mul(sig.1) == sig.0.add(pk.mul(reduced_challenge).to_affine()) {
            Ok(())
        } else {
            Err(Error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    #[test]
    fn schnorr_primitive() {
        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let msg = Base::random(&mut rng);

        let (sk, pk) = Schnorr::keygen(&mut rng);
        let sig = Schnorr::sign((sk, pk), msg, &mut rng);

        assert!(Schnorr::verify(msg, pk, sig).is_ok());

        let fake_msg = Base::random(&mut rng);
        assert!(Schnorr::verify(fake_msg, pk, sig).is_err());

        let fake_pk = ExtendedPoint::random(&mut rng).to_affine();
        assert!(Schnorr::verify(msg, fake_pk, sig).is_err());
    }
}
