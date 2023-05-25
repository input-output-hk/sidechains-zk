//! This module defines and implements the Rescue block cipher

use crate::rescue::{
    PseudoRandomPermutation, RescuePRP, RescueParameters, RescueState, STATE_WIDTH,
};
use ff::PrimeField;
use rand_core::{CryptoRng, RngCore};
use std::marker::PhantomData;

#[derive(Debug, Default)]
/// RescueBlockCipher
pub struct RescueBlockCipher<F: PrimeField, RP: RescueParameters<F>> {
    prime_field: PhantomData<F>,
    rescue_parameters: PhantomData<RP>,
}

impl<F: PrimeField, RP: RescueParameters<F>> RescueBlockCipher<F, RP> {
    /// Generate a key for the rescue cipher
    pub fn keygen<R: RngCore + CryptoRng>(_rng: &mut R) -> RescueState<F> {
        RescuePRP::<F, RP>::keygen()
    }

    fn apply_key_stream(
        data: Vec<RescueState<F>>,
        key: RescueState<F>,
        encrypt: bool,
    ) -> Vec<RescueState<F>> {
        let mut output: Vec<RescueState<F>> = data;

        let prp = RescuePRP::<F, RP>::new(Some(key));

        let mut input = [F::ZERO; STATE_WIDTH];

        for val in output.iter_mut() {
            let key_stream = prp.permute(&input);

            *val = if encrypt {
                state_add(val, &key_stream)
            } else {
                state_sub(val, &key_stream)
            };

            input[0] += F::ONE;
        }

        output
    }

    /// Encrypt a message under a given key
    pub fn encrypt(msg: Vec<RescueState<F>>, key: RescueState<F>) -> Vec<RescueState<F>> {
        Self::apply_key_stream(msg, key, true)
    }

    /// Decrypt a ciphertext under a given key
    pub fn decrypt(ctxt: Vec<RescueState<F>>, key: RescueState<F>) -> Vec<RescueState<F>> {
        Self::apply_key_stream(ctxt, key, false)
    }
}

fn state_add<F: PrimeField>(st_a: &RescueState<F>, st_b: &RescueState<F>) -> RescueState<F> {
    st_a.iter()
        .zip(st_b.iter())
        .map(|(&a, &b)| a + b)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

fn state_sub<F: PrimeField>(st_a: &RescueState<F>, st_b: &RescueState<F>) -> RescueState<F> {
    st_a.iter()
        .zip(st_b.iter())
        .map(|(&a, &b)| a - b)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

// #[cfg(test)]
// mod tests {
//     use ff::Field;
//     use pasta_curves::Fp;
//
//     use super::*;
//     use crate::RescueParametersPallas;
//     use rand_chacha::ChaCha8Rng;
//     use rand_core::SeedableRng;
//
//     #[test]
//     fn encrypt_decrypt() {
//         let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
//         let key = [
//             Fp::random(&mut rng),
//             Fp::random(&mut rng),
//             Fp::random(&mut rng),
//             Fp::random(&mut rng),
//         ];
//         let msg = vec![
//             [
//                 Fp::random(&mut rng),
//                 Fp::random(&mut rng),
//                 Fp::random(&mut rng),
//                 Fp::random(&mut rng),
//             ];
//             4
//         ];
//
//         let ctxt = RescueBlockCipher::<Fp, RescueParametersPallas>::encrypt(msg.clone(), key);
//
//         let decryption = RescueBlockCipher::<Fp, RescueParametersPallas>::decrypt(ctxt, key);
//
//         assert_eq!(msg, decryption)
//     }
// }
