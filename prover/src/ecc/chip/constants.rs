//! Constants required for the ECC chip.

use arrayvec::ArrayVec;
use group::{
    ff::{Field, PrimeField},
    Curve,
};
use halo2_proofs::utils::arithmetic::lagrange_interpolate;
use halo2curves::{jubjub, CurveAffine};

/// Window size for fixed-base scalar multiplication
pub const FIXED_BASE_WINDOW_SIZE: usize = 3;

/// $2^{`FIXED_BASE_WINDOW_SIZE`}$
pub const H: usize = 1 << FIXED_BASE_WINDOW_SIZE;

/// Number of windows for a full-width scalar
pub const NUM_WINDOWS: usize =
    (jubjub::Scalar::NUM_BITS as usize + FIXED_BASE_WINDOW_SIZE - 1) / FIXED_BASE_WINDOW_SIZE;

/// Number of windows for a short signed scalar
pub const NUM_WINDOWS_SHORT: usize =
    (L_SCALAR_SHORT + FIXED_BASE_WINDOW_SIZE - 1) / FIXED_BASE_WINDOW_SIZE;

/// $\ell_\mathsf{value}$
/// Number of bits in an unsigned short scalar.
pub(crate) const L_SCALAR_SHORT: usize = 64;
