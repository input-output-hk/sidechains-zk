//! Elliptic curve operations.
//!
//! See the [Elliptic curve cryptography documentation][crate::docs::ecc].
use std::fmt::Debug;

use halo2_proofs::{
    circuit::{Chip, Layouter, Value},
    plonk::Error,
};
use halo2curves::CurveAffine;


pub mod chip;

