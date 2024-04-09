//! This module defines and implements the rescue pseudo random permutation

use ff::PrimeField;
use rand::rngs::OsRng;
use std::marker::PhantomData;

use super::rescue_parameters::*;

/// Defines a pseudo random permutation
pub trait PseudoRandomPermutation {
    /// The domain of the permutation
    type Domain;

    /// The key domain
    type Key;

    /// It creates a new permutation object. If key is empty, the fixed key variant is used.
    fn new(key: Option<Self::Key>) -> Self;

    /// Key sampler
    fn keygen() -> Self::Key;

    /// The permutation function
    fn permute(&self, inp: &Self::Domain) -> Self::Domain;
}

/// Struct defining the rescue prp. It contains the key of the instantiation, cached round keys
///  and the parameters for the rescue permutation implementation
#[derive(Debug, Default)]
pub struct RescuePRP<F: PrimeField, RP: RescueParameters<F>> {
    _key: RescueState<F>,
    round_keys: StateVectorsMatrix<F>,
    _phantom_f: PhantomData<F>,
    _phantom_rp: PhantomData<RP>,
}

impl<F, RP> PseudoRandomPermutation for RescuePRP<F, RP>
where
    F: PrimeField,
    RP: RescueParameters<F>,
{
    type Domain = RescueState<F>;
    type Key = RescueState<F>;

    // All zero key for the key variant

    /// Returns a new instantiation of a rescue permutation for some given key.
    /// If a key is given it caches the key scheduling constants, otherwise
    /// it uses the round constants for the fixed key \[0,0,0,0\]
    fn new(key: Option<RescueState<F>>) -> Self {
        if let Some(key) = key {
            Self {
                _key: key,
                round_keys: Self::core_permutation(&key, &RP::KI_VECTOR),
                _phantom_f: Default::default(),
                _phantom_rp: Default::default(),
            }
        } else {
            Self {
                _key: [F::ZERO; STATE_WIDTH],
                round_keys: RP::RC_VECTOR,
                _phantom_f: Default::default(),
                _phantom_rp: Default::default(),
            }
        }
    }

    // Samples a random key
    fn keygen() -> RescueState<F> {
        let mut key: RescueState<F> = [F::ZERO; STATE_WIDTH];
        key.iter_mut().for_each(|k| *k = F::random(OsRng));
        key
    }

    // An implementation of the PRP. We use the `core_permutation` helper function.
    fn permute(&self, inp: &RescueState<F>) -> RescueState<F> {
        // We run the core permutation on the input using the key scheduling constants
        // Unwrap never panics due to the type system
        *Self::core_permutation(inp, &self.round_keys)
            .last()
            .unwrap()
    }
}

impl<F, RP> RescuePRP<F, RP>
where
    F: PrimeField,
    RP: RescueParameters<F>,
{
    // implements the core algorithm used in rescue. That is, given an input state st, a matrix M and a vector V it applies:
    // st -> st + V[0]
    // for each round
    //      st -> M st^{1/5} + V[2r+1]
    //      st -> M st^{5} + V[2r+2]
    // We keep the matrix fixed since we always use the MDS matrix. The only other matrix used is the
    // key injection matrix, but since we hardcode the derived constants we never use this.
    //
    // We return an array containing all the intermediate states since this is needed for the
    // key_scheduling algorithm.
    //
    // We implement this to avoid code duplication.
    fn core_permutation(
        inp: &RescueState<F>,
        vector: &StateVectorsMatrix<F>,
    ) -> StateVectorsMatrix<F>
    where
        F: PrimeField,
        RP: RescueParameters<F>,
    {
        let mut result: StateVectorsMatrix<F> = Default::default();

        let state = &mut inp.clone();

        // st -> st + RC where RC are the initial round constants
        state.iter_mut().zip(vector[0]).for_each(|(s, c)| *s += c);

        result[0] = *state;

        // each iteration is a full round: first we apply the pow5_inv S-Box + affine transofrmation and second half
        // the pow5 S-Box + affine transformation
        for r in 0..N_ROUNDS {
            // st -> st^5
            sbox_pow5_inv::<F, RP>(state);
            // st -> M st + v[2r+1] where M is the MDS matrix
            linear_op::<F, STATE_WIDTH>(state, &RP::mds(), &vector[2 * r + 1]);

            result[2 * r + 1] = *state;

            // st -> st^{1/5}
            sbox_pow5(state);
            // st -> M st + RC where M is the MDS matrix
            linear_op::<F, STATE_WIDTH>(state, &RP::mds(), &vector[2 * r + 2]);

            result[2 * r + 2] = *state;
        }
        result
    }
}

// Helper functions

// returns the inner product of two rescue states
fn inner_product<F: PrimeField>(a: &[F], b: &[F]) -> F {
    assert_eq!(a.len(), b.len());

    a.iter()
        .zip(b.iter())
        .fold(F::ZERO, |acc, (&a, &b)| acc + (a * b))
}

// applies the map st -> M st + constant
fn linear_op<F: PrimeField, const N: usize>(
    state: &mut [F; N],
    matrix: &[[F; N]; N],
    constant: &[F; N],
) {
    let mut new_state = [F::ZERO; N];

    matrix
        .iter()
        .zip(constant.iter())
        .enumerate()
        .for_each(|(i, (row, c))| new_state[i] = inner_product(row, state) + c);
    *state = new_state;
}

// maps each element s of state to s^5
fn sbox_pow5<F: PrimeField>(state: &mut [F]) {
    state
        .iter_mut()
        .for_each(|s| *s = s.pow_vartime([5, 0, 0, 0]))
}

// maps each element s of state to s^{1/5 mod p-1} where p is the modulus of the prime field
fn sbox_pow5_inv<F, RP>(state: &mut [F])
where
    F: PrimeField,
    RP: RescueParameters<F>,
{
    state.iter_mut().for_each(|s| *s = s.pow_vartime(RP::A_INV))
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::rescue::primitive::{RescueParametersPallas, RescueParametersVesta};
//     use crate::rescue::test_vectors;
//     use pasta_curves::{Fp, Fq};
//
//     #[test]
//     fn test_rescue_permutation_pallas() {
//         // We test the fixed key variant
//         let rescue_prp = RescuePRP::<Fp, RescueParametersPallas>::new(None);
//         for (input_state, correct_output_state) in test_vectors::PALLAS_TEST_VECTORS {
//             // We compute the output:
//             let output_state = rescue_prp.permute(&input_state);
//             assert_eq!(output_state, correct_output_state);
//         }
//
//         // We next test the keyed variant
//         for (key, input_state, correct_output_state) in test_vectors::PALLAS_TEST_VECTORS_KEYED {
//             let rescue_prp = RescuePRP::<Fp, RescueParametersPallas>::new(Some(key));
//             let output_state = rescue_prp.permute(&input_state);
//             assert_eq!(output_state, correct_output_state);
//         }
//     }
//
//     #[test]
//     fn test_rescue_permutation_vesta() {
//         // We test the fixed key variant
//         let rescue_prp = RescuePRP::<Fq, RescueParametersVesta>::new(None);
//         for (input_state, correct_output_state) in test_vectors::VESTA_TEST_VECTORS {
//             // We compute the output
//             let output_state = rescue_prp.permute(&input_state);
//             assert_eq!(output_state, correct_output_state);
//         }
//         //
//         // We next test the keyed variant
//         for (key, input_state, correct_output_state) in test_vectors::VESTA_TEST_VECTORS_KEYED {
//             let rescue_prp = RescuePRP::<Fq, RescueParametersVesta>::new(Some(key));
//             let output_state = rescue_prp.permute(&input_state);
//             assert_eq!(output_state, correct_output_state);
//         }
//     }
// }
