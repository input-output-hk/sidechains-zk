//! This module contains constants and trait needed for the rescue permutation parameters

use ff::PrimeField;

/// Rescue state width is 4
pub(crate) const STATE_WIDTH: usize = 4;

/// Number of rounds for the rescue permutation
/// 12 rounds correspond to 128 bits security
pub(crate) const N_ROUNDS: usize = 12;

// Number of state vectors used in permutation
pub(crate) const N_CONSTS: usize = N_ROUNDS * 2 + 1;

// 255 bit integer exponent in little endian encoded integer
pub(crate) type EEncoding = [u64; 4];

// Rescue state defined by 4 field elements
pub(crate) type RescueState<F> = [F; STATE_WIDTH];

// Rescue MDS matrix defined by 4x4 matrix of field elements
pub(crate) type RescueMatrix<F> = [[F; STATE_WIDTH]; STATE_WIDTH];

// Rescue Key injection matrix used in Rescue cipher
pub(crate) type StateVectorsMatrix<F> = [RescueState<F>; N_CONSTS];

/// This trait defines rescue  permutation constants and associated funcitons to access
/// them. The exponentiation s-box always has value 5 for our choice of fields and is
/// hardcoded in the main gate implementation.
pub trait RescueParameters<F: PrimeField>: Default {
    /// parameter 5^-1 (mod p - 1) in little endian encoding where p is the modulus of the base
    /// field over which the curve is defined
    const A_INV: EEncoding;
    /// MDS matrix
    const MDS: RescueMatrix<F>;
    /// Key injection vector. This is fixed, independent of the key and is precomputed
    const KI_VECTOR: StateVectorsMatrix<F>;
    /// Round constants of fixed-key permutation. The round constants are stored in the order they
    /// are needed, i.e. first the initial round constant, then the two round constants for the
    /// first round, the second round and so on.
    const RC_VECTOR: StateVectorsMatrix<F>;

    /// Returns the MDS matrix from the config
    fn mds() -> RescueMatrix<F> {
        Self::MDS
    }

    /// Returns the r-th round constant vector
    fn round_constants_state(r: usize) -> RescueState<F> {
        assert!(r < N_CONSTS);
        Self::RC_VECTOR[r]
    }

    /// Returns the r-th vector of the key injection matrix
    fn key_injection_state(r: usize) -> RescueState<F> {
        assert!(r < N_CONSTS);
        Self::KI_VECTOR[r]
    }
}
