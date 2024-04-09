//! Elliptic curve operations.
//!
//! See the [Elliptic curve cryptography documentation][crate::docs::ecc].
use std::fmt::Debug;

use halo2_proofs::{
    arithmetic::CurveAffine,
    circuit::{Chip, Layouter, Value},
    plonk::Error,
};

pub mod chip;

